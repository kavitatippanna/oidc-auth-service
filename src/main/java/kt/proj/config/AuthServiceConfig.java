package kt.proj.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** This class represents the Authentication service configuration. */
public class AuthServiceConfig {
  private List<OIDCClientConfig> oidcClients;
  private UserTokenConfig tokenConfig;

  public AuthServiceConfig() {}

  @JsonProperty("oidc_clients")
  public List<OIDCClientConfig> getOidcClients() {
    return oidcClients;
  }

  @JsonProperty("user_token")
  public UserTokenConfig getTokenConfig() {
    return tokenConfig;
  }

  @Override
  public String toString() {
    return "AuthServiceConfig{"
        + "oidcClients="
        + oidcClients
        + ", tokenConfig="
        + tokenConfig
        + '}';
  }
}
