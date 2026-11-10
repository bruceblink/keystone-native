package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class LegacyUserRoleTest {
    @Test
    void originalUserAndRoleRoutesSupportCrudAndAssignment() {
        String token = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        given().auth().oauth2(token).when().get("/system/role/list").then().statusCode(200).body("data.total", greaterThanOrEqualTo(2));
        String roleKey = "COMPAT_" + System.nanoTime();
        int roleId = given().auth().oauth2(token).contentType(JSON)
                .body("{\"roleKey\":\"" + roleKey + "\",\"roleName\":\"Compatibility Role\",\"dataScope\":\"DEPT\"}")
                .when().post("/system/role").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(token).when().get("/system/role/" + roleId).then().statusCode(200).body("data.code", is(roleKey));
        given().auth().oauth2(token).contentType(JSON).body("{\"dataScope\":\"ALL\"}")
                .when().put("/system/role/" + roleId + "/dataScope").then().statusCode(200).body("data.dataScope", is("ALL"));

        String username = "legacy_" + System.nanoTime();
        int userId = given().auth().oauth2(token).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"nickname\":\"Legacy User\",\"roleCode\":\"USER\"}")
                .when().post("/system/users").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(token).when().get("/system/users?username=" + username).then().statusCode(200).body("data.total", is(1));
        given().auth().oauth2(token).when().post("/system/role/" + roleId + "/users/" + userId + "/grant/bulk").then().statusCode(200);
        given().auth().oauth2(token).when().delete("/system/users/" + userId).then().statusCode(200);
        given().auth().oauth2(token).when().delete("/system/role/" + roleId).then().statusCode(200);
    }
}
