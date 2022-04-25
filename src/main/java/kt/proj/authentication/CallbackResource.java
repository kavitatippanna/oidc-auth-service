package kt.proj.authentication;

import static kt.proj.authentication.AuthCtx.COOKIE_VALUE_SEPARATOR;

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriInfo;
import kt.proj.common.ErrorCode;
import kt.proj.common.ErrorResponseHandler;
import kt.proj.models.UserTokenModel;
import org.jboss.resteasy.reactive.RestCookie;
import org.jboss.resteasy.reactive.RestResponse;

@Path("/oauth/callback")
public class CallbackResource {
  private static final Logger LOGGER = Logger.getLogger(CallbackResource.class.getName());

  @Inject CallbackService socialAuthCallbackService;
  private static final String PROVIDER_KEY = "provider";
  private static final String STATE_KEY = "state";

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  public RestResponse handleCallback(@Context UriInfo uriInfo, @RestCookie String socialCookie)
      throws Exception {
    Map<String, String> cookieInfo = getCookieInfo(socialCookie);
    String provider = cookieInfo.get(PROVIDER_KEY);
    LOGGER.info("Processing callback from provider: " + provider);
    String userToken = null;
    try {
      userToken =
          socialAuthCallbackService.handleCallback(
              uriInfo.getRequestUri(), provider, cookieInfo.get(STATE_KEY));
    } catch (Exception e) {
      LOGGER.fine("Code call back failed");
      return ErrorResponseHandler.buildErrorResponse(
          RestResponse.Status.BAD_REQUEST,
          ErrorCode.INVALID_INPUT,
          "Unsuccessful processing code callback from provider " + provider);
    }
    return RestResponse.ResponseBuilder.create(RestResponse.Status.OK)
        .entity(createUserTokenModel(userToken))
        .build();
  }

  private Map<String, String> getCookieInfo(String socialCookie) {
    Map<String, String> cookieInfo = new HashMap<>();
    if (socialCookie == null) {
      return cookieInfo;
    }
    String[] cvalues = socialCookie.split(COOKIE_VALUE_SEPARATOR);
    cookieInfo.put(PROVIDER_KEY, cvalues[0]);
    cookieInfo.put(STATE_KEY, cvalues[1]);
    return cookieInfo;
  }

  private UserTokenModel createUserTokenModel(String token) {
    UserTokenModel userToken = new UserTokenModel();
    userToken.setUserToken(token);
    return userToken;
  }
}
