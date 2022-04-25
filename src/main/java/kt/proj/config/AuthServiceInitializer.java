package kt.proj.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import java.io.File;
import java.io.IOException;
import javax.enterprise.inject.Produces;
import javax.inject.Singleton;

public class AuthServiceInitializer {
  @Produces
  @Singleton
  public AuthServiceConfig getInstance() {
    ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
    File file = new File(classLoader.getResource("auth-service.yaml").getFile());

    ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
    try {
      return mapper.readValue(file, AuthServiceConfig.class);
    } catch (IOException e) {
      throw new RuntimeException("Could not load Auth service configuration.", e);
    }
  }
}
