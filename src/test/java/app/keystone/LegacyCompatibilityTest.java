package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class LegacyCompatibilityTest {
    @Test
    void publicLoginCompatibilityEndpointsRemainAvailable() {
        given().when().get("/getConfig").then().statusCode(200).body("data.captchaEnabled", is(false)).body("data.registerEnabled", is(false));
        given().when().get("/captchaImage").then().statusCode(200).body("data.captchaEnabled", is(false));
        given().when().get("/login/rsa-public-key").then().statusCode(200).body("data.publicKey", containsString("BEGIN PUBLIC KEY"));
        given().when().get("/health").then().statusCode(200).body("data.status", is("UP"));
    }

    @Test
    void authenticatedRouterCompatibilityEndpointReturnsTree() {
        String token = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        given().auth().oauth2(token).when().get("/getLoginUserInfo").then().statusCode(200).body("success", is(true));
        given().auth().oauth2(token).when().get("/getRouters").then().statusCode(200).body("success", is(true));
    }
}
