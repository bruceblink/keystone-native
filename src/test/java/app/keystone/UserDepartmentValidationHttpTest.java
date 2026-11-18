package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;

/** 使用真实 HTTP 验证用户部门编号错误不会触发数据库外键失败。 */
@QuarkusTest
class UserDepartmentValidationHttpTest extends AuthTestFixture {
    @Test
    void invalidAndMissingDepartmentIdsAreRejectedWithoutChangingUsers() {
        String admin = login("admin", "password");
        String username = "dept_validation_" + System.nanoTime();
        String existingDepartment = null;
        String replacementDepartment = null;
        String userId = null;

        try {
            existingDepartment = createDepartment(admin, "部门原值");
            replacementDepartment = createDepartment(admin, "部门新值");
            userId = createUser(admin, username, existingDepartment);

            int invalidRequest = 0;
            for (String departmentId : new String[] {"not-a-uuid", UUID.randomUUID().toString()}) {
                String candidateUsername = username + "_create_" + invalidRequest++;
                given().auth().oauth2(admin).contentType(JSON)
                        .body(userRequest(candidateUsername, "待创建用户", departmentId))
                        .when().post("/v1/users")
                        .then().statusCode(422)
                        .body("error.code", is("validation_failed"));
                given().auth().oauth2(admin)
                        .when().get("/v1/users?username=" + candidateUsername)
                        .then().statusCode(200).body("data.items", empty());

                given().auth().oauth2(admin).contentType(JSON)
                        .body(updateRequest("错误更新名称", departmentId))
                        .when().put("/v1/users/" + userId)
                        .then().statusCode(422)
                        .body("error.code", is("validation_failed"));
                given().auth().oauth2(admin)
                        .when().get("/v1/users/" + userId)
                        .then().statusCode(200)
                        .body("data.deptId", is(existingDepartment))
                        .body("data.displayName", is("原始用户名称"));
            }

            given().auth().oauth2(admin).contentType(JSON)
                    .body(updateRequest("有效部门更新", replacementDepartment))
                    .when().put("/v1/users/" + userId)
                    .then().statusCode(200)
                    .body("data.deptId", is(replacementDepartment));
        } finally {
            if (userId != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
            }
            if (existingDepartment != null) {
                given().auth().oauth2(admin).when().delete("/v1/departments/" + existingDepartment).then().statusCode(200);
            }
            if (replacementDepartment != null) {
                given().auth().oauth2(admin).when().delete("/v1/departments/" + replacementDepartment).then().statusCode(200);
            }
        }
    }

    private static String createDepartment(String admin, String name) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"dept_validation_" + System.nanoTime()
                        + "\",\"name\":\"" + name + "\",\"sortOrder\":1,\"enabled\":true}")
                .when().post("/v1/departments")
                .then().statusCode(201).extract().path("data.id");
    }

    private static String createUser(String admin, String username, String departmentId) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body(userRequest(username, "原始用户名称", departmentId))
                .when().post("/v1/users")
                .then().statusCode(201).extract().path("data.id");
    }

    private static String userRequest(String username, String displayName, String departmentId) {
        String user = username == null ? "" : "\"username\":\"" + username + "\",";
        return "{" + user + "\"password\":\"password\",\"displayName\":\"" + displayName
                + "\",\"deptId\":\"" + departmentId + "\",\"roleCodes\":[\"USER\"]}";
    }

    private static String updateRequest(String displayName, String departmentId) {
        return "{\"displayName\":\"" + displayName + "\",\"deptId\":\"" + departmentId
                + "\",\"clearDept\":true}";
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password
                        + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
