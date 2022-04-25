package kt.proj.authentication;

import static kt.proj.authentication.AuthCtx.COOKIE_VALUE_SEPARATOR;

import java.util.logging.Logger;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.NewCookie;
import org.jboss.resteasy.reactive.RestQuery;
import org.jboss.resteasy.reactive.RestResponse;

@Path("/authenticate")
@Produces(MediaType.APPLICATION_JSON)
public class AuthenticationResource {
  private static final Logger LOGGER = Logger.getLogger(AuthenticationResource.class.getName());
  public static final String COOKIE_NAME = "socialCookie";

  @Inject AuthenticationService authnService;

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  public RestResponse authenticate(@RestQuery String provider) {
    LOGGER.info("Authentication request received for provider: " + provider);
    AuthCtx authCtx = authnService.getAuthnCtx(provider);
    // State for CSRF protection
    NewCookie cookie =
        new NewCookie(
            COOKIE_NAME,
            String.format(
                "%s%s%s", authCtx.getProvider(), COOKIE_VALUE_SEPARATOR, authCtx.getState()));

    return RestResponse.ResponseBuilder.create(RestResponse.Status.FOUND)
        .location(authCtx.getRedirectUrl())
        .cookie(cookie)
        .build();
  }
}
