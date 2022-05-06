package kt.proj.profile;

import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import java.util.logging.Logger;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.SecurityContext;
import kt.proj.authentication.filter.SecurityFilter;
import kt.proj.common.ErrorCode;
import kt.proj.common.ErrorResponseHandler;
import kt.proj.common.UserTokenManager;
import kt.proj.config.OIDCProviders;
import kt.proj.models.UserProfileModel;
import org.jboss.resteasy.reactive.RestResponse;

@Path("/myprofile")
public class UserProfileResource {
  private static final Logger LOGGER = Logger.getLogger(UserProfileResource.class.getName());
  @Inject UserProfileService userProfileService;
  @Inject SecurityContext securityContext;

  @Inject
  public UserProfileResource(OIDCProviders providers, UserTokenManager tokenManager) {}

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  public RestResponse getUserProfile() {
    SecurityFilter.UserTokenPrincipal tokenPrincipal =
        (SecurityFilter.UserTokenPrincipal) securityContext.getUserPrincipal();
    UserInfo userInfo = userProfileService.getMyProfile(tokenPrincipal.getUserToken());
    if (userInfo == null) {
      LOGGER.fine("Unable to fetch profile for user " + tokenPrincipal.getName());
      return ErrorResponseHandler.buildErrorResponse(
          RestResponse.Status.INTERNAL_SERVER_ERROR,
          ErrorCode.SERVER_SIDE_ERROR,
          "Unable to fetch profile for user " + tokenPrincipal.getName());
    }

    return RestResponse.ResponseBuilder.create(RestResponse.Status.OK)
        .entity(createUserProfileModel(userInfo))
        .build();
  }

  /**
   * Generate API model for user profile
   *
   * @param userInfo
   * @return
   */
  private UserProfileModel createUserProfileModel(UserInfo userInfo) {
    UserProfileModel profileModel = new UserProfileModel();
    profileModel.setUserName(userInfo.getName());
    profileModel.setEmail(userInfo.getEmailAddress());
    profileModel.setSubjectId(userInfo.getSubject().getValue());
    return profileModel;
  }
}
