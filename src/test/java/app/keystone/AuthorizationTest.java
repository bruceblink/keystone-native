package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class AuthorizationTest {
    @Test
    void legacyHealthEndpointRemainsPublic() {
        given().when().get("/health").then().statusCode(200).body("data.status", is("UP"));
    }

    @Test
    void protectedResourcesRejectAnonymousRequests() {
        given().when().get("/v1/users").then().statusCode(401);
        given().when().get("/v1/menus").then().statusCode(401);
        given().when().get("/v1/operation-logs").then().statusCode(401);
    }
}
