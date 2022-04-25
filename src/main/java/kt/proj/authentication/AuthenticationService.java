package kt.proj.authentication;

import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.logging.Logger;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import kt.proj.common.AppConfig;
import kt.proj.common.AuthServiceException;
import kt.proj.config.OIDCClientConfig;
import kt.proj.config.OIDCProviders;

@ApplicationScoped
public class AuthenticationService {
  private static final Logger LOGGER = Logger.getLogger(AuthenticationService.class.getName());

  @Inject OIDCProviders oidcProviders;

  /**
   * Gets an authentication context to use for provider redirection
   *
   * @param provider
   * @return authentication context with information as redirect url and provider name
   */
  public AuthCtx getAuthnCtx(String provider) {
    AuthCtx authCtx = new AuthCtx();
    authCtx.setRedirectUrl(getRedirectUrl(provider, authCtx));
    authCtx.setProvider(provider);
    return authCtx;
  }

  /**
   * Constructs the redirect url for sending to the provider for authentication
   *
   * @param provider
   * @param authCtx
   * @return
   */
  private URI getRedirectUrl(String provider, AuthCtx authCtx) {
    URI authzEndpoint =
        oidcProviders
            .getAuthorizationEndpoint(provider)
            .orElseThrow(
                () ->
                    new AuthServiceException(
                        "Authz endpoint info not available for provider " + provider));

    OIDCClientConfig clientConfig =
        oidcProviders
            .getOIDCClient(provider)
            .orElseThrow(
                () ->
                    new AuthServiceException(
                        "No client config available for provider " + provider));

    ClientID clientID = new ClientID(clientConfig.getClientId());
    Scope scope = new Scope();
    for (String scopeValue : clientConfig.getScopes()) {
      scope.add(scopeValue);
    }

    URI callback = null;
    try {
      callback = new URI(AppConfig.CALLBACK_URL);
    } catch (URISyntaxException e) {
      LOGGER.info("Invalid callback url config");
      return null;
    }
    State state = new State();
    authCtx.setState(state.getValue());
    AuthorizationRequest request =
        new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), clientID)
            .scope(scope)
            .state(state)
            .redirectionURI(callback)
            .endpointURI(authzEndpoint)
            .build();
    return request.toURI();
  }
}
