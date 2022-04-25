package kt.proj.models;

import kt.proj.common.ErrorCode;

public class ErrorModel {
  ErrorCode code;
  String message;

  public ErrorModel() {}

  public ErrorModel(ErrorCode code, String message) {
    this.code = code;
    this.message = message;
  }

  public ErrorCode getCode() {
    return code;
  }

  public void setCode(ErrorCode code) {
    this.code = code;
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }
}
