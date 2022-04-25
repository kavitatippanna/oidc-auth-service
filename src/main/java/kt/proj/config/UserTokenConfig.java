package kt.proj.config;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Arrays;
import javax.inject.Singleton;

/** Class that represents the configuration to issue User tokens for authenticated clients. */
@Singleton
public class UserTokenConfig {
  private String issuer;
  private String audience;
  private byte[] privateKey;
  private long tokenExpiry;
  private String signatureAlgorithm;
  private int keySize;

  @JsonProperty("issuer")
  public String getIssuer() {
    return issuer;
  }

  @JsonProperty("audience")
  public String getAudience() {
    return audience;
  }

  @JsonProperty("private_key")
  public byte[] getPrivateKey() {
    return privateKey;
  }

  @JsonProperty("expiry")
  public long getTokenExpiry() {
    return tokenExpiry;
  }

  @JsonProperty("signature_algorithm")
  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  @JsonProperty("key_size")
  public int getKeySize() {
    return keySize;
  }

  @Override
  public String toString() {
    return "UserTokenConfig{"
        + "issuer='"
        + issuer
        + '\''
        + ", audience='"
        + audience
        + '\''
        + ", privateKey="
        + Arrays.toString(privateKey)
        + ", tokenExpiry="
        + tokenExpiry
        + ", signatureAlgorithm='"
        + signatureAlgorithm
        + '\''
        + ", keySize="
        + keySize
        + '}';
  }
}
