package kt.proj.authentication.filter;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import java.security.Principal;
import java.util.Set;
import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
import kt.proj.common.UserTokenManager;

@Provider
@Priority(Priorities.AUTHENTICATION)
public class SecurityFilter implements ContainerRequestFilter {
  private static final String AUTHORIZATION_HEADER = "Authorization";

  private static final Set<String> publicURIs = Set.of("/authenticate", "/oauth/callback");

  @Inject UserTokenManager tokenManager;

  @Override
  public void filter(ContainerRequestContext requestContext) {
    String authzHeader = requestContext.getHeaderString(AUTHORIZATION_HEADER);
    Runnable errorResponse =
        () -> requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());

    /* Skip authorization check for public URIs viz. login & OIDC callback. */
    if (publicURIs.contains(requestContext.getUriInfo().getPath())) {
      return;
    } else if (authzHeader == null) {
      errorResponse.run();
      return;
    }

    String userToken;
    try {
      userToken = BearerAccessToken.parse(authzHeader).getValue();
    } catch (ParseException e) {
      errorResponse.run();
      return;
    }

    tokenManager
        .getValidatedUserToken(userToken)
        .ifPresentOrElse(
            jwtToken ->
                requestContext.setSecurityContext(
                    new SecurityContext() {
                      @Override
                      public Principal getUserPrincipal() {
                        return new UserTokenPrincipal(jwtToken);
                      }

                      @Override
                      public boolean isUserInRole(String r) {
                        return false;
                      }

                      @Override
                      public boolean isSecure() {
                        return true;
                      }

                      @Override
                      public String getAuthenticationScheme() {
                        return "Bearer";
                      }
                    }),
            errorResponse);
  }

  public static class UserTokenPrincipal implements Principal {
    private final JWT userToken;

    public UserTokenPrincipal(JWT userToken) {
      this.userToken = userToken;
    }

    @Override
    public String getName() {
      return UserTokenManager.getTokenClaims(userToken).getSubject();
    }

    public JWT getUserToken() {
      return userToken;
    }
  }
}
