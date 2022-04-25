package kt.proj.authentication;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

@QuarkusTest
public class UserProfileResourceTest {
  @Test
  public void testGetProfileUnautheticated() {
    given().when().get("/myprofile").then().statusCode(401);
  }
}
