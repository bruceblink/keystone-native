package app.keystone;

import app.keystone.auth.MfaService;
import app.keystone.auth.TotpService;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 使用真实 HTTP 和 MySQL 验证用户创建、更新及导入中的角色分配权限。 */
@QuarkusTest
class UserRoleAssignmentPermissionHttpTest extends AuthTestFixture {
    @Inject MfaService mfa;

    @Test
    void createAndUpdateRequireRoleAssignOnlyWhenRolesAreRequested() {
        String admin = login("admin", "password");
        String suffix = Long.toString(System.nanoTime());
        String noAssignRole = null;
        String assignRole = null;
        String noAssignUser = null;
        String assignUser = null;
        String noRoleTarget = null;
        String assignedTarget = null;
        try {
            noAssignRole = createRole(admin, "NO_ASSIGN_" + suffix,
                    List.of("user:read", "user:create", "user:update", "role:manage", "permission:manage"));
            assignRole = createRole(admin, "CAN_ASSIGN_" + suffix,
                    List.of("user:read", "user:create", "user:update", "role:assign"));
            noAssignUser = createUser(admin, "no_assign_actor_" + suffix, noAssignRole);
            assignUser = createUser(admin, "assign_actor_" + suffix, assignRole);
            String noAssign = login("no_assign_actor_" + suffix, "password");
            String canAssign = login("assign_actor_" + suffix, "password");

            String rejectedUsername = "rejected_role_create_" + suffix;
            given().auth().oauth2(noAssign).contentType(JSON)
                    .body(userRequest(rejectedUsername, List.of("USER")))
                    .when().post("/v1/users").then().statusCode(403)
                    .body("error.code", is("permission_denied"));
            given().auth().oauth2(admin).when().get("/v1/users?username=" + rejectedUsername)
                    .then().statusCode(200).body("data.items", empty());

            noRoleTarget = given().auth().oauth2(noAssign).contentType(JSON)
                    .body(userRequest("no_role_target_" + suffix, null))
                    .when().post("/v1/users").then().statusCode(201)
                    .body("data.roles", empty()).extract().path("data.id");
            given().auth().oauth2(noAssign).contentType(JSON)
                    .body("{\"roleCodes\":[\"USER\"]}")
                    .when().put("/v1/users/" + noRoleTarget).then().statusCode(403)
                    .body("error.code", is("permission_denied"));
            given().auth().oauth2(admin).when().get("/v1/users/" + noRoleTarget)
                    .then().statusCode(200).body("data.roles", empty());

            assignedTarget = given().auth().oauth2(canAssign).contentType(JSON)
                    .body(userRequest("assigned_target_" + suffix, List.of("USER")))
                    .when().post("/v1/users").then().statusCode(201)
                    .body("data.roles", is(List.of("USER"))).extract().path("data.id");
            given().auth().oauth2(canAssign).contentType(JSON)
                    .body("{\"roleCodes\":[\"USER\"]}")
                    .when().put("/v1/users/" + noRoleTarget).then().statusCode(200)
                    .body("data.roles", is(List.of("USER")));

            // 空列表只清除角色；Phoenix 对空列表不要求 role:assign。
            given().auth().oauth2(noAssign).contentType(JSON)
                    .body("{\"roleCodes\":[]}")
                    .when().put("/v1/users/" + noRoleTarget).then().statusCode(200)
                    .body("data.roles", empty());
        } finally {
            deleteUser(admin, assignedTarget);
            deleteUser(admin, noRoleTarget);
            deleteUser(admin, assignUser);
            deleteUser(admin, noAssignUser);
            deleteRole(admin, assignRole);
            deleteRole(admin, noAssignRole);
        }
    }

    @Test
    void importRequiresRoleAssignOnlyForRowsThatContainRoleIds() {
        String admin = login("admin", "password");
        String suffix = Long.toString(System.nanoTime());
        String noAssignRole = null;
        String assignRole = null;
        String targetRole = null;
        String noAssignUser = null;
        String assignUser = null;
        String deniedUsername = "rejected_role_import_" + suffix;
        String noRoleUsername = "no_role_import_" + suffix;
        String assignedUsername = "assigned_role_import_" + suffix;
        try {
            noAssignRole = createRole(admin, "IMPORT_NO_ASSIGN_" + suffix,
                    List.of("user:read", "user:import", "mfa:manage", "role:manage", "permission:manage"));
            assignRole = createRole(admin, "IMPORT_CAN_ASSIGN_" + suffix,
                    List.of("user:read", "user:import", "mfa:manage", "role:assign"));
            targetRole = createRole(admin, "IMPORT_TARGET_" + suffix, List.of("user:read"));
            noAssignUser = createUser(admin, "import_no_assign_" + suffix, noAssignRole);
            assignUser = createUser(admin, "import_assign_" + suffix, assignRole);
            String noAssign = enrollAndLoginAal2(noAssignUser, "import_no_assign_" + suffix);
            String canAssign = enrollAndLoginAal2(assignUser, "import_assign_" + suffix);
            String targetRoleId = roleId(admin, "IMPORT_TARGET_" + suffix);

            importUser(noAssign, deniedUsername, targetRoleId)
                    .body("data.total", is(1)).body("data.success", is(0))
                    .body("data.failed[0].code", is("permission_denied"));
            given().auth().oauth2(admin).when().get("/v1/users?username=" + deniedUsername)
                    .then().statusCode(200).body("data.items", empty());

            importUser(noAssign, noRoleUsername, "")
                    .body("data.total", is(1)).body("data.success", is(1)).body("data.failed", empty());
            importUser(canAssign, assignedUsername, targetRoleId)
                    .body("data.total", is(1)).body("data.success", is(1)).body("data.failed", empty());
            given().auth().oauth2(admin).when().get("/v1/users?username=" + assignedUsername)
                    .then().statusCode(200)
                    .body("data.items[0].roles", is(List.of("IMPORT_TARGET_" + suffix)));
        } finally {
            cleanupImportedUser(admin, assignedUsername);
            cleanupImportedUser(admin, noRoleUsername);
            cleanupImportedUser(admin, deniedUsername);
            deleteUser(admin, assignUser);
            deleteUser(admin, noAssignUser);
            deleteRole(admin, targetRole);
            deleteRole(admin, assignRole);
            deleteRole(admin, noAssignRole);
        }
    }

    private static String createRole(String admin, String code, List<String> permissions) {
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"角色授权回归\",\"enabled\":true}")
                .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"permissions\":" + jsonArray(permissions) + "}")
                .when().put("/v1/roles/" + id + "/permissions").then().statusCode(200);
        return code;
    }

    private static String createUser(String admin, String username, String roleCode) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body(userRequest(username, List.of(roleCode)))
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
    }

    private static String userRequest(String username, List<String> roleCodes) {
        String roles = roleCodes == null ? "" : ",\"roleCodes\":" + jsonArray(roleCodes);
        return "{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"角色授权测试\"" + roles + "}";
    }

    private static String jsonArray(List<String> values) {
        return values.stream().map(value -> "\"" + value + "\"")
                .collect(java.util.stream.Collectors.joining(",", "[", "]"));
    }

    private String enrollAndLoginAal2(String userId, String username) {
        String aal1 = login(username, "password");
        var enrollment = given().auth().oauth2(aal1).contentType(JSON)
                .when().post("/v1/auth/mfa/enroll").then().statusCode(201).extract();
        String code = new TotpService().code(enrollment.path("data.secret"), Instant.now());
        var verified = given().auth().oauth2(aal1).contentType(JSON)
                .body("{\"challengeId\":\"" + enrollment.path("data.challengeId") + "\",\"code\":\"" + code + "\"}")
                .when().post("/v1/auth/mfa/enroll/verify").then().statusCode(200).extract();
        assertTrue(mfa.setRequired(userId, true));
        var challenge = given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(401).extract();
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"challengeId\":\"" + challenge.path("data.challengeId")
                        + "\",\"code\":\"" + verified.path("data.recoveryCodes[0]") + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/mfa/verify").then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private static io.restassured.response.ValidatableResponse importUser(String token, String username, String roleId) {
        byte[] workbook = ExcelExporter.export(
                List.of("用户名", "昵称", "密码", "角色ID"),
                List.of(List.of(username, "导入角色测试", "password", roleId)));
        return given().auth().oauth2(token)
                .multiPart("file", "users.xlsx", workbook, ExcelExporter.CONTENT_TYPE)
                .when().post("/v1/users/import").then().statusCode(200);
    }

    private static String roleId(String admin, String code) {
        return given().auth().oauth2(admin).queryParam("keyword", code).when().get("/v1/roles")
                .then().statusCode(200).extract().path("data.items[0].id");
    }

    private static void cleanupImportedUser(String admin, String username) {
        List<String> ids = given().auth().oauth2(admin).when().get("/v1/users?username=" + username)
                .then().statusCode(200).extract().path("data.items.id");
        if (ids != null) ids.forEach(id -> deleteUser(admin, id));
    }

    private static void deleteUser(String admin, String id) {
        if (id != null) given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
    }

    private static void deleteRole(String admin, String id) {
        if (id != null) {
            String roleId = roleId(admin, id);
            given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
