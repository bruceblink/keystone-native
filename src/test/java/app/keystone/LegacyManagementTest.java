package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

@QuarkusTest
class LegacyManagementTest extends AuthTestFixture {
    @Test
    void originalManagementRoutesAreAvailable() {
        String token = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        String[] paths = {"/system/depts", "/system/depts/dropdown", "/system/dict/types", "/system/dict/data/list", "/system/configs", "/system/menus", "/system/menus/dropdown", "/system/notices", "/system/post/list"};
        for (String path : paths) given().auth().oauth2(token).when().get(path).then().statusCode(200).body("success", is(true));
        given().auth().oauth2(token).when().delete("/system/configs/cache").then().statusCode(200).body("data.cleared", is(true));

        int id = given().auth().oauth2(token).contentType(JSON)
                .body("{\"postCode\":\"compat-" + System.nanoTime() + "\",\"postName\":\"Compatibility Post\",\"postSort\":1}")
                .when().post("/system/post").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(token).when().get("/system/post/" + id).then().statusCode(200).body("data.name", is("Compatibility Post"));
        given().auth().oauth2(token).when().delete("/system/post?ids=" + id).then().statusCode(200).body("data.deleted", is(1));
    }

    @Test
    void legacyDepartmentRoutesRespectUserDataScope() {
        String admin = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        String suffix = String.valueOf(System.nanoTime());
        String code = "LEGACY_SCOPE_" + suffix;
        int departmentId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"Legacy scoped department\"}")
                .when().post("/system/dept").then().statusCode(201).extract().path("data.id");
        String username = "legacy_scope_" + suffix;
        int userId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Legacy Scoped User\",\"deptId\":" + departmentId + ",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        try {
            String user = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                    .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
            int rootId = given().auth().oauth2(admin).when().get("/system/depts")
                    .then().statusCode(200).extract().path("data.find { it.code == 'ROOT' }.id");
            given().auth().oauth2(user).when().get("/system/depts")
                    .then().statusCode(200).body("data.code", hasItem(code)).body("data.code", not(hasItem("ROOT")));
            given().auth().oauth2(user).when().get("/system/dept/" + rootId).then().statusCode(404);
        } finally {
            given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
            given().auth().oauth2(admin).when().delete("/system/dept/" + departmentId).then().statusCode(200);
        }
    }
}
