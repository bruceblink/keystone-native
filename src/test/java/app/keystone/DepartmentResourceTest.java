package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

@QuarkusTest
class DepartmentResourceTest extends AuthTestFixture {
    @Test
    void regularUserSeesOnlyTheirOwnDepartment() {
        String admin = login("admin", "password");
        String suffix = String.valueOf(System.nanoTime());
        String code = "TEST_DEPT_" + suffix;
        int departmentId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"Test department\"}")
                .when().post("/v1/departments").then().statusCode(201).extract().path("data.id");
        String username = "dept_scope_" + suffix;
        int userId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Scoped User\",\"deptId\":" + departmentId + ",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        try {
            String user = login(username, "password");
            given().auth().oauth2(user).when().get("/v1/departments")
                    .then().statusCode(200)
                    .body("data.code", hasItem(code))
                    .body("data.code", not(hasItem("ROOT")));
        } finally {
            given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
            given().auth().oauth2(admin).when().delete("/v1/departments/" + departmentId).then().statusCode(200);
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
