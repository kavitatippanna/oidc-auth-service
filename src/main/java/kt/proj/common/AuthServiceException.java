package kt.proj.common;

/**
 * Class to represent Exceptions thrown while processing requests in Authentication service domain.
 */
public class AuthServiceException extends RuntimeException {
  public AuthServiceException(String message) {
    super(message);
  }

  public AuthServiceException(String message, Throwable cause) {
    super(message, cause);
  }
}
