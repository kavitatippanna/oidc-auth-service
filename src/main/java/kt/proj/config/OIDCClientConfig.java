package kt.proj.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.net.URI;
import java.util.Set;

/**
 * This class represents a registered OpenID Connect client used to perform Authorization code grant
 * flow.
 */
public class OIDCClientConfig {
  private String providerName;
  private URI discoveryURI;
  private String clientId;
  private String clientSecret;
  private Set<String> scopes;

  @JsonProperty("provider_name")
  public String getProviderName() {
    return providerName;
  }

  @JsonProperty("discovery_url")
  public URI getDiscoveryURI() {
    return discoveryURI;
  }

  @JsonProperty("client_id")
  public String getClientId() {
    return clientId;
  }

  @JsonProperty("client_secret")
  public String getClientSecret() {
    return clientSecret;
  }

  @JsonProperty("request_scopes")
  public Set<String> getScopes() {
    return scopes;
  }

  @Override
  public String toString() {
    return "OIDCClientConfig{"
        + "providerName='"
        + providerName
        + '\''
        + ", discoveryURI="
        + discoveryURI
        + ", clientId='"
        + clientId
        + '\''
        + ", clientSecret='"
        + clientSecret
        + '\''
        + ", scopes="
        + scopes
        + '}';
  }
}
