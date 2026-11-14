package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AuthResourceTest extends AuthTestFixture {

    @Test
    void adminCanLoginAndReceiveRefreshToken() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(200).body("success", is(true))
                .body("data.accessToken", not(emptyOrNullString()))
                .body("data.refreshToken", not(emptyOrNullString()))
                .body("data.token", nullValue())
                .body("data.sessionId", not(emptyOrNullString()))
                .body("data.clientId", is("web"))
                .body("data.roles[0]", is("ADMIN"));
    }

    @Test
    void accessTokenCarriesCanonicalAuthenticationClaims() throws Exception {
        String token = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(token.split("\\.")[1]), java.nio.charset.StandardCharsets.UTF_8);
        var claims = new com.fasterxml.jackson.databind.ObjectMapper().readTree(payload);
        assertEquals("access", claims.path("type").asText());
        assertEquals("AAL1", claims.path("aal").asText());
        assertTrue(claims.path("amr").isArray());
        assertEquals("pwd", claims.path("amr").get(0).asText());
    }

    @Test
    void invalidCredentialsAreRejected() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(401).body("success", is(false));
    }

    @Test
    void repeatedFailuresAreRateLimited() {
        String admin = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        String username = "rate_limit_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Rate Limit User\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        for (int i = 0; i < 10; i++) {
            int status = given().contentType(JSON).body("{\"username\":\"" + username + "\",\"password\":\"wrong\"}")
                    .when().post("/v1/auth/login").then().extract().statusCode();
            assertEquals(401, status);
        }
        given().contentType(JSON).body("{\"username\":\"" + username + "\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login").then().statusCode(429);
        given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
    }

    @Test
    void secondLoginIsRejectedUnlessExplicitlyForced() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200);
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(409).body("success", is(false));
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).body("data.accessToken", not(emptyOrNullString()));
    }

    @Test
    void refreshTokenRotatesAndLogoutRevokesIt() {
        var login = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract();
        String access = login.path("data.accessToken");
        String refresh = login.path("data.refreshToken");
        var rotated = given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(200).extract();
        String replacement = rotated.path("data.refreshToken");
        access = rotated.path("data.accessToken");
        given().auth().oauth2(access).contentType(JSON).body("{\"refreshToken\":\"" + replacement + "\"}")
                .when().post("/v1/auth/logout").then().statusCode(200);
        given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
        given().contentType(JSON).body("{\"refreshToken\":\"" + replacement + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
    }

    @Test
    void refreshClientMismatchRevokesTheWholeTokenFamily() {
        String refresh = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"clientId\":\"desktop\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.refreshToken");
        given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\",\"clientId\":\"mobile\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
        given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\",\"clientId\":\"desktop\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
    }

    @Test
    void logoutInvalidatesTheAccessTokenImmediately() {
        var response = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract();
        String access = response.path("data.accessToken");
        String refresh = response.path("data.refreshToken");
        given().auth().oauth2(access).when().get("/v1/profile").then().statusCode(200);
        given().auth().oauth2(access).contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/logout").then().statusCode(200);
        given().auth().oauth2(access).when().get("/v1/profile").then().statusCode(401);
    }
}
