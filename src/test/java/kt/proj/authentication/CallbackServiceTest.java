package kt.proj.authentication;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.junit.QuarkusMock;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.Cookie;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

@QuarkusTest
@TestHTTPEndpoint(CallbackResource.class)
public class CallbackServiceTest {
  @Test
  public void testTokenEndpoint() {
    CallbackService cbSrvMock = Mockito.mock(CallbackService.class);
    QuarkusMock.installMockForType(cbSrvMock, CallbackService.class);

    Cookie socialCookie =
        new Cookie.Builder(AuthenticationResource.COOKIE_NAME, "Google:abcstate").build();
    given()
        .redirects()
        .follow(false)
        .cookie(socialCookie)
        .queryParam("code", "abc")
        .queryParam("state", "abcstate")
        .when()
        .get()
        .then()
        .statusCode(200);
  }

  @Test
  public void testTokenEndpointNoCode() {
    Cookie socialCookie =
        new Cookie.Builder(AuthenticationResource.COOKIE_NAME, "Google:abcstate").build();
    given()
        .redirects()
        .follow(false)
        .cookie(socialCookie)
        .queryParam("state", "abcstate")
        .when()
        .get()
        .then()
        .statusCode(400)
        .body(containsString("Unsuccessful processing code callback from provider"));
  }
}
