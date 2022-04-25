package kt.proj.common;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import java.text.ParseException;
import java.time.Duration;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Logger;
import javax.inject.Inject;
import javax.inject.Singleton;
import kt.proj.config.AuthServiceConfig;
import kt.proj.config.OIDCProviders;
import kt.proj.config.UserTokenConfig;
import org.jetbrains.annotations.NotNull;

@Singleton
public class UserTokenManager {
  private static final Logger LOGGER = Logger.getLogger(UserTokenManager.class.getName());
  public static final String PROVIDER_CLAIM = "prd";

  private final OIDCProviders oidcProviders;
  private final UserTokenConfig tokenConfig;

  /*
   * Cache of Access tokens for authenticated users with jti of the user token issued
   * by Auth service serving as the key.
   */
  private final Cache<String, AccessToken> userTokens;

  /* JWT Signer & Verifier to sign & verify user tokens respectively. */
  private final JWSSigner signer;
  private final JWSVerifier verifier;
  private final JWSHeader tokenHeader;

  @Inject
  public UserTokenManager(AuthServiceConfig authServiceConfig, OIDCProviders providers)
      throws JOSEException {
    this.tokenConfig = authServiceConfig.getTokenConfig();
    this.oidcProviders = providers;
    userTokens =
        Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(Duration.ofSeconds(tokenConfig.getTokenExpiry()))
            .build();

    RSAKey userTokenJWK =
        new RSAKeyGenerator(tokenConfig.getKeySize())
            .keyIDFromThumbprint(true)
            .keyUse(KeyUse.SIGNATURE)
            .generate();
    signer = new RSASSASigner(userTokenJWK);
    verifier = new RSASSAVerifier(userTokenJWK.toPublicJWK());
    tokenHeader =
        new JWSHeader.Builder(JWSAlgorithm.parse(tokenConfig.getSignatureAlgorithm()))
            .type(JOSEObjectType.JWT)
            .build();
  }

  /**
   * Issues a minted User token based on the specified identity token.
   *
   * @param idToken Id token to obtain user claims.
   * @param accessToken Access token to be managed for subsequent access to User info endpoint.
   * @return User token minted corresponding to the identity token obtained from OIDC provider.
   * @throws AuthServiceException if token issuance failed.
   */
  public @NotNull String issueToken(@NotNull JWT idToken, @NotNull AccessToken accessToken)
      throws AuthServiceException {
    String jwtId = UUID.randomUUID().toString();
    Date issueTime = new Date();
    JWTClaimsSet idTokenClaims = getTokenClaims(idToken);

    JWTClaimsSet userTokenClaims =
        oidcProviders
            .getProviderName(idTokenClaims.getIssuer())
            .map(
                providerClaim ->
                    new JWTClaimsSet.Builder()
                        .subject(idTokenClaims.getSubject())
                        .jwtID(jwtId)
                        .issuer(tokenConfig.getIssuer())
                        .audience(tokenConfig.getAudience())
                        .issueTime(issueTime)
                        .expirationTime(
                            new Date(issueTime.getTime() + tokenConfig.getTokenExpiry() * 1000))
                        .claim(PROVIDER_CLAIM, providerClaim)
                        .build())
            .orElseThrow(() -> new AuthServiceException("Unsupported identity token"));

    SignedJWT userToken = new SignedJWT(tokenHeader, userTokenClaims);
    try {
      userToken.sign(signer);
    } catch (JOSEException e) {
      LOGGER.fine("Failed to sign user token: " + e.getMessage());
      throw new AuthServiceException("Failed to sign user token", e);
    }
    userTokens.put(jwtId, accessToken);
    return userToken.serialize();
  }

  /**
   * Validates the specified user token for signature, issuer & expiration and returns the
   * corresponding access token if valid.
   *
   * @param userToken for which the corresponding access token must be returned.
   * @return AccessToken if the user token is valid.
   */
  public Optional<AccessToken> getAccessToken(@NotNull JWT userToken) throws AuthServiceException {
    JWTClaimsSet userTokenClaims = getTokenClaims(userToken);
    return Optional.ofNullable(userTokens.getIfPresent(userTokenClaims.getJWTID()));
  }

  /**
   * Validates and returns the parsed JWT user token.
   *
   * @param userToken to be validated.
   * @return validated & parsed JWT user token.
   */
  public Optional<JWT> getValidatedUserToken(@NotNull String userToken) {
    try {
      /* Verify the issuer & token expiration if the token signature is valid. */
      SignedJWT signedJWT = SignedJWT.parse(userToken);
      if (signedJWT.verify(verifier)) {
        JWTClaimsSet userTokenClaims = getTokenClaims(signedJWT);
        if (tokenConfig.getIssuer().equals(userTokenClaims.getIssuer())
            && userTokenClaims.getAudience().contains(tokenConfig.getAudience())
            && new Date().before(userTokenClaims.getExpirationTime())
            && userTokens.getIfPresent(userTokenClaims.getJWTID()) != null) {
          return Optional.of(signedJWT);
        }
      }
    } catch (JOSEException | ParseException e) {
      LOGGER.fine("Could not verify user token." + e.getMessage());
    }
    return Optional.empty();
  }

  /**
   * Invalidates the specified user token so that subsequent call for validation would fail.
   *
   * @param userToken that needs to be invalidated; called during user logout.
   */
  public void invalidateToken(@NotNull JWT userToken) throws AuthServiceException {
    JWTClaimsSet userTokenClaims = getTokenClaims(userToken);
    userTokens.invalidate(userTokenClaims.getJWTID());
  }

  /**
   * Utility method to parse & return token claims.
   *
   * @param token for which the claims must be returned.
   * @return Set of claims present in the JWT token.
   */
  public static JWTClaimsSet getTokenClaims(@NotNull JWT token) {
    try {
      return token.getJWTClaimsSet();
    } catch (ParseException e) {
      LOGGER.fine("Unable to parse token claims: " + e.getMessage());
      throw new AuthServiceException("Could not parse token claims", e);
    }
  }
}
