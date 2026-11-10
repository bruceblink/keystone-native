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
    }

    @Test
    void adminCanLoginAndReceiveRefreshToken() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(200).body("success", is(true))
                .body("data.accessToken", not(emptyOrNullString()))
                .body("data.refreshToken", not(emptyOrNullString()))
                .body("data.roles[0]", is("ADMIN"));
    }

    @Test
    void invalidCredentialsAreRejected() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(401).body("success", is(false));
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
}
