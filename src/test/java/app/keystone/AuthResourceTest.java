package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import javax.sql.DataSource;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.emptyOrNullString;

@QuarkusTest
class AuthResourceTest {
    @Inject DataSource dataSource;

    @BeforeEach
    void enableDevelopmentFixture() throws Exception {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_user SET must_change_password = false WHERE username = 'admin'")) { p.executeUpdate(); }
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = (SELECT id FROM sys_user WHERE username = 'admin') AND revoked_at IS NULL")) { p.executeUpdate(); }
    }

    @Test
    void adminCanLoginAndReceiveRefreshToken() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(200).body("success", is(true))
                .body("data.accessToken", not(emptyOrNullString()))
                .body("data.refreshToken", not(emptyOrNullString()))
                .body("data.sessionId", not(emptyOrNullString()))
                .body("data.clientId", is("web"))
                .body("data.roles[0]", is("ADMIN"));
    }

    @Test
    void invalidCredentialsAreRejected() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(401).body("success", is(false));
    }

    @Test
    void secondLoginIsRejectedUnlessExplicitlyForced() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200);
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(409).body("success", is(false));
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).body("data.token", not(emptyOrNullString()));
    }

    @Test
    void refreshTokenRotatesAndLogoutRevokesIt() {
        String refresh = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.refreshToken");
        String replacement = given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(200).extract().path("data.refreshToken");
        given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
        given().contentType(JSON).body("{\"refreshToken\":\"" + replacement + "\"}")
                .when().post("/v1/auth/logout").then().statusCode(200);
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
