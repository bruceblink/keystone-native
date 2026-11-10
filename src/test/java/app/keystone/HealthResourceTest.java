package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class HealthResourceTest {
    @Test
    void healthIsAvailable() {
        given().when().get("/v1/health").then().statusCode(200).body("success", is(true)).body("data.status", is("UP"));
    }
}
