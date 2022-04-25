package kt.proj.config;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import java.io.IOException;
import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import javax.inject.Inject;
import javax.inject.Singleton;
import org.jetbrains.annotations.NotNull;

/**
 * This class represents the configured OIDC providers and uses the OIDC discovery endpoint to
 * retrieve authorization, token & userinfo endpoints used in various OIDC flows.
 */
@Singleton
public class OIDCProviders {
  private static final Logger LOGGER = Logger.getLogger(OIDCProviders.class.getName());
  private final Map<String, OIDCProviderMetadata> providerConfig;

  private final Map<String, OIDCClientConfig> clientConfig;

  @Inject
  public OIDCProviders(@NotNull AuthServiceConfig authServiceConfig) {
    providerConfig =
        authServiceConfig.getOidcClients().stream()
            .collect(
                Collectors.toUnmodifiableMap(
                    clientConfig -> clientConfig.getProviderName().toLowerCase(),
                    clientConfig -> {
                      try {
                        return OIDCProviderMetadata.resolve(
                            new Issuer(clientConfig.getDiscoveryURI()));
                      } catch (IOException | GeneralException e) {
                        LOGGER.severe("Could not initialize OIDC provider.");
                        throw new RuntimeException(
                            "Unable to load IdP configuration for OIDC provider: "
                                + clientConfig.getProviderName(),
                            e);
                      }
                    }));

    clientConfig =
        authServiceConfig.getOidcClients().stream()
            .collect(
                Collectors.toUnmodifiableMap(
                    clientConfig -> clientConfig.getProviderName().toLowerCase(),
                    Function.identity()));
  }

  /**
   * Returns OIDC Authorization endpoint for the specified provider.
   *
   * @param providerName Name of the configured provider.
   * @return Authorization endpoint URI if the provider is configured.
   */
  public Optional<URI> getAuthorizationEndpoint(@NotNull String providerName) {
    OIDCProviderMetadata metadata = providerConfig.get(providerName.toLowerCase());
    return Optional.ofNullable(metadata != null ? metadata.getAuthorizationEndpointURI() : null);
  }

  /**
   * Returns OIDC Token endpoint for the specified provider.
   *
   * @param providerName Name of the configured provider.
   * @return Token endpoint URI if the provider is configured.
   */
  public Optional<URI> getTokenEndpoint(@NotNull String providerName) {
    OIDCProviderMetadata metadata = providerConfig.get(providerName.toLowerCase());
    return Optional.ofNullable(metadata != null ? metadata.getTokenEndpointURI() : null);
  }

  /**
   * Returns OIDC User information endpoint for the specified provider.
   *
   * @param providerName Name of the configured provider.
   * @return Userinfo endpoint URI if the provider is configured.
   */
  public Optional<URI> getUserInfoEndpoint(@NotNull String providerName) {
    OIDCProviderMetadata metadata = providerConfig.get(providerName.toLowerCase());
    return Optional.ofNullable(metadata != null ? metadata.getUserInfoEndpointURI() : null);
  }

  /**
   * Returns the provider name based on the specified issuer.
   *
   * @param issuer URI of the issuer.
   * @return Configured provider name associated with the issuer URI.
   */
  public Optional<String> getProviderName(@NotNull String issuer) {
    return providerConfig.entrySet().stream()
        .filter(entry -> entry.getValue().getIssuer().getValue().equals(issuer))
        .map(Map.Entry::getKey)
        .findFirst();
  }

  public Optional<OIDCClientConfig> getOIDCClient(@NotNull String providerName) {
    OIDCClientConfig metadata = clientConfig.get(providerName.toLowerCase());
    return Optional.ofNullable(metadata);
  }
}
