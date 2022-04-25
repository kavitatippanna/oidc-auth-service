package kt.proj.common;

import kt.proj.models.ErrorModel;
import org.jboss.resteasy.reactive.RestResponse;

public class ErrorResponseHandler {
  public static RestResponse buildErrorResponse(
      RestResponse.Status status, ErrorCode code, String message) {
    ErrorModel errorModel = new ErrorModel(code, message);
    return RestResponse.ResponseBuilder.create(status).entity(errorModel).build();
  }
}
