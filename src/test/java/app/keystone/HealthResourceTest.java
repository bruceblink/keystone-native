package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class HealthResourceTest {
    @Test
    void healthIsAvailable() {
        given().when().get("/v1/health").then().statusCode(200)
                .header("X-Content-Type-Options", is("nosniff"))
                .header("X-Frame-Options", is("DENY"))
                .header("Referrer-Policy", is("no-referrer"))
                .header("Cache-Control", is("no-store, max-age=0"))
                .body("success", is(true)).body("data.status", is("UP"));
    }
}
