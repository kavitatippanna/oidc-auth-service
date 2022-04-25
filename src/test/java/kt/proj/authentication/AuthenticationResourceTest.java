package kt.proj.authentication;

import io.quarkus.test.common.http.TestHTTPEndpoint;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;

@QuarkusTest
@TestHTTPEndpoint(AuthenticationResource.class)
public class AuthenticationResourceTest {

    @Test
    public void testTokenEndpoint() {
        given()
                .redirects().follow(false)
                .queryParam("provider", "Google")
                .when().get()
                .then()
                .header("Location", containsString("google"))
                .cookie(AuthenticationResource.COOKIE_NAME)
                .statusCode(302);
    }

}