package kt.proj.authentication;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import kt.proj.authentication.filter.SecurityFilter;
import kt.proj.common.UserTokenManager;
import org.jboss.resteasy.reactive.RestResponse;

@Path("/logout")
@Produces(MediaType.APPLICATION_JSON)
public class LogoutResource {
  @Inject UserTokenManager tokenManager;
  @Inject SecurityContext securityContext;

  @GET
  public RestResponse logout() {
    SecurityFilter.UserTokenPrincipal tokenPrincipal =
        (SecurityFilter.UserTokenPrincipal) securityContext.getUserPrincipal();
    tokenManager.invalidateToken(tokenPrincipal.getUserToken());
    return RestResponse.ResponseBuilder.create(RestResponse.Status.OK)
        .entity("You are logged out")
        .build();
  }
}
