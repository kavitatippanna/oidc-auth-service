package kt.proj.authentication;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Logger;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import kt.proj.common.AppConfig;
import kt.proj.common.AuthServiceException;
import kt.proj.common.UserTokenManager;
import kt.proj.config.OIDCClientConfig;
import kt.proj.config.OIDCProviders;

@ApplicationScoped
public class CallbackService {
  private static final Logger LOGGER = Logger.getLogger(CallbackService.class.getName());

  @Inject OIDCProviders oidcProviders;
  @Inject UserTokenManager tokenManager;

  public String handleCallback(URI requestURI, String provider, String storedState)
      throws AuthServiceException {
    LOGGER.info("Processing callback from provider " + provider);
    if (requestURI == null || provider == null) {
      LOGGER.fine("Invalid inputs");
      throw new AuthServiceException("Require nun-null URI and provider ");
    }
    AuthorizationCode code = getAuthzCode(requestURI, storedState);
    return getUserToken(code, provider);
  }

  private AuthorizationCode getAuthzCode(URI requestURI, String storedState) {
    AuthenticationResponse authResp = null;
    try {
      authResp = AuthenticationResponseParser.parse(requestURI);
    } catch (ParseException e) {
      LOGGER.fine("Error retrieving authz code");
      throw new AuthServiceException("Error retrieving authz code");
    }

    if (authResp instanceof AuthenticationErrorResponse) {
      ErrorObject error = ((AuthenticationErrorResponse) authResp).getErrorObject();
      LOGGER.fine("Error response for authz code request.");
      throw new AuthServiceException("Error response for authz code request. Error obj: " + error);
    }

    AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) authResp;
    if (!verifyState(successResponse.getState(), storedState)) {
      LOGGER.fine("Incorrect state received in response.");
      throw new AuthServiceException("Incorrect state received in response");
    }

    return successResponse.getAuthorizationCode();
  }

  private boolean verifyState(State state, String storedState) {
    if (storedState == null || state == null) {
      return false;
    }
    return state.getValue().equals(storedState);
  }

  private String getUserToken(AuthorizationCode authCode, String provider)
      throws AuthServiceException {
    URI callback = null;
    try {
      callback = new URI(AppConfig.CALLBACK_URL);
    } catch (URISyntaxException e) {
      throw new AuthServiceException("Invalid callback uri configured");
    }
    AuthorizationGrant codeGrant = new AuthorizationCodeGrant(authCode, callback);

    OIDCClientConfig clientConfig =
        oidcProviders
            .getOIDCClient(provider)
            .orElseThrow(
                () ->
                    new AuthServiceException(
                        "No client config available for provider " + provider));

    // The credentials to authenticate the client at the token endpoint
    ClientID clientID = new ClientID(clientConfig.getClientId());
    Secret clientSecret = new Secret(clientConfig.getClientSecret());
    ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

    // The token endpoint
    URI tokenEndpoint =
        oidcProviders
            .getTokenEndpoint(provider)
            .orElseThrow(
                () ->
                    new AuthServiceException(
                        "Token endpoint info not available for provider " + provider));

    TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);
    TokenResponse tokenResponse = null;
    try {
      tokenResponse = OIDCTokenResponseParser.parse(request.toHTTPRequest().send());
    } catch (ParseException | IOException e) {
      throw new AuthServiceException("Parsing error", e);
    }

    if (!tokenResponse.indicatesSuccess()) {
      TokenErrorResponse errorResponse = tokenResponse.toErrorResponse();
      LOGGER.fine("Error response from token endpoint  " + tokenEndpoint.toString());
      throw new AuthServiceException("Couldn't get access token from provider");
    }

    OIDCTokenResponse successResponse = (OIDCTokenResponse) tokenResponse.toSuccessResponse();

    // Get the ID and access token
    JWT idToken = successResponse.getOIDCTokens().getIDToken();
    AccessToken accessToken = successResponse.getOIDCTokens().getAccessToken();
    return tokenManager.issueToken(idToken, accessToken);
  }
}
