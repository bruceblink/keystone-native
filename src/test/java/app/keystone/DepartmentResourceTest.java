package app.keystone;

import app.keystone.role.RoleRepository;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

@QuarkusTest
class DepartmentResourceTest extends AuthTestFixture {
    @Inject RoleRepository roles;

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

    @Test
    void restrictedDepartmentWriterCannotMutateOutsideItsScope() {
        String admin = login("admin", "password");
        String suffix = String.valueOf(System.nanoTime());
        String departmentCode = "WRITE_SCOPE_" + suffix;
        String roleCode = "WRITE_SCOPE_ROLE_" + suffix;
        String username = "write_scope_" + suffix;
        Integer departmentId = null;
        Integer childId = null;
        Integer userId = null;
        boolean roleCreated = false;
        try {
            departmentId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + departmentCode + "\",\"name\":\"Write scope department\"}")
                    .when().post("/v1/departments").then().statusCode(201).extract().path("data.id");
            userId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Scoped Writer\",\"deptId\":" + departmentId + ",\"roleCodes\":[\"USER\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

            roles.create(roleCode, "Write scope role");
            roleCreated = true;
            roles.updateExtended(roleCode, null, null, "SELF", null);
            roles.assignPermissions(roleCode, java.util.List.of("department:read", "department:write"));
            roles.assignUsers(roleCode, java.util.List.of(userId.longValue()));

            String user = login(username, "password");
            given().auth().oauth2(user).contentType(JSON)
                    .body("{\"code\":\"ROOT_FORBIDDEN_" + suffix + "\",\"name\":\"Root forbidden\"}")
                    .when().post("/v1/departments").then().statusCode(403);
            childId = given().auth().oauth2(user).contentType(JSON)
                    .body("{\"code\":\"CHILD_ALLOWED_" + suffix + "\",\"name\":\"Child allowed\",\"parentId\":" + departmentId + "}")
                    .when().post("/v1/departments").then().statusCode(201).extract().path("data.id");

            int rootId = given().auth().oauth2(admin).when().get("/v1/departments")
                    .then().statusCode(200).extract().path("data.find { it.code == 'ROOT' }.id");
            given().auth().oauth2(user).contentType(JSON)
                    .body("{\"name\":\"Root update forbidden\"}")
                    .when().put("/v1/departments/" + rootId).then().statusCode(403);
            given().auth().oauth2(user).when().delete("/v1/departments/" + rootId).then().statusCode(403);
            given().auth().oauth2(user).contentType(JSON)
                    .body("{\"code\":\"LEGACY_ROOT_FORBIDDEN_" + suffix + "\",\"name\":\"Legacy root forbidden\"}")
                    .when().post("/system/dept").then().statusCode(403);
            given().auth().oauth2(user).contentType(JSON)
                    .body("{\"name\":\"Legacy root update forbidden\"}")
                    .when().put("/system/dept/" + rootId).then().statusCode(403);
            given().auth().oauth2(user).when().delete("/system/dept/" + rootId).then().statusCode(403);
        } finally {
            if (roleCreated && userId != null) {
                try { roles.revokeUsers(roleCode, java.util.List.of(userId.longValue())); }
                catch (RuntimeException ignored) { }
            }
            if (roleCreated) {
                try { roles.delete(roleCode); } catch (java.util.NoSuchElementException | IllegalArgumentException ignored) { }
            }
            if (userId != null) given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
            if (childId != null) given().auth().oauth2(admin).when().delete("/v1/departments/" + childId).then().statusCode(200);
            if (departmentId != null) given().auth().oauth2(admin).when().delete("/v1/departments/" + departmentId).then().statusCode(200);
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
