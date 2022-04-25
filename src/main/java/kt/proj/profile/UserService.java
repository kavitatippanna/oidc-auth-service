package kt.proj.profile;

import static kt.proj.common.UserTokenManager.PROVIDER_CLAIM;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.logging.Logger;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.core.SecurityContext;
import kt.proj.authentication.filter.SecurityFilter;
import kt.proj.common.AuthServiceException;
import kt.proj.common.UserTokenManager;
import kt.proj.config.OIDCProviders;
import org.jetbrains.annotations.NotNull;

@ApplicationScoped
public class UserService {
  private static final Logger LOGGER = Logger.getLogger(UserService.class.getName());
  private final OIDCProviders oidcProviders;
  private final UserTokenManager tokenManager;

  @Inject SecurityContext securityContext;
  /*
   * User information cache to avoid fetching user profile from OIDC provider frequently. The cache
   * uses provider & user id as key to resolve conflicts for the same user id present across
   * multiple OIDC providers.
   */
  private final LoadingCache<String, UserInfo> userInfoCache;

  @Inject
  public UserService(OIDCProviders providers, UserTokenManager tokenManager) {
    this.oidcProviders = providers;
    this.tokenManager = tokenManager;
    userInfoCache =
        Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(Duration.ofMinutes(5))
            .build(this::getUserInfo);
  }

  /**
   * Retrieves user profile information for the specified subject from OIDC provider using userinfo
   * endpoint.
   *
   * @param userId Subject for which user profile is requested.
   * @return UserInfo if the request to OIDC provider is successful.
   */
  private @NotNull UserInfo getUserInfo(String userId) throws AuthServiceException {
    SecurityFilter.UserTokenPrincipal tokenPrincipal =
        (SecurityFilter.UserTokenPrincipal) securityContext.getUserPrincipal();
    JWT userToken = tokenPrincipal.getUserToken();

    String providerName =
        (String) UserTokenManager.getTokenClaims(userToken).getClaim(PROVIDER_CLAIM);
    URI userInfoEndpoint = oidcProviders.getUserInfoEndpoint(providerName).orElse(null);

    return tokenManager
        .getAccessToken(userToken)
        .map(
            accessToken -> {
              UserInfoRequest userInfoRequest = new UserInfoRequest(userInfoEndpoint, accessToken);
              UserInfoResponse userInfoResponse;
              try {
                HTTPResponse httpResponse = userInfoRequest.toHTTPRequest().send();
                userInfoResponse = UserInfoResponse.parse(httpResponse);
              } catch (IOException | ParseException e) {
                throw new AuthServiceException("Failed to retrieve user profile", e);
              }

              /* The request failed due to invalid or expired token. */
              if (!userInfoResponse.indicatesSuccess()) {
                ErrorObject error = userInfoResponse.toErrorResponse().getErrorObject();
                String errorMessage = "UserInfo request failed with error: " + error;
                LOGGER.fine(errorMessage);
                throw new AuthServiceException(errorMessage);
              }
              return userInfoResponse.toSuccessResponse().getUserInfo();
            })
        .orElseThrow(() -> new AuthServiceException("Invalid user profile request"));
  }

  /**
   * Retrieves profile information for the authenticated user represented in token
   *
   * @param userToken
   * @return
   */
  public UserInfo getMyProfile(JWT userToken) {
    String providerName =
        (String) UserTokenManager.getTokenClaims(userToken).getClaim(PROVIDER_CLAIM);
    String userId = UserTokenManager.getTokenClaims(userToken).getSubject();
    return userInfoCache.get(providerName + "#" + userId);
  }
}
