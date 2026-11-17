package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 验证角色成员的查询、分配、撤销和批量失败回滚边界。 */
@QuarkusTest
class RoleResourceHttpTest extends AuthTestFixture {
    /** V46 初始化的系统 ADMIN 角色 UUID；请求测试不修改其成员关系。 */
    private static final String SYSTEM_ADMIN_ROLE_ID = "2f57b9e0-836d-5f15-97a3-d4be27dc0bef";

    /** 通过真实 HTTP 验证角色自身的创建、更新、权限绑定和删除生命周期。 */
    @Test
    void administratorCanManageRoleLifecycle() {
        String admin = login("admin", "password");
        String roleId = null;
        try {
            String roleCode = "HTTP_ROLE_LIFECYCLE_" + System.nanoTime();
            roleId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + roleCode + "\",\"name\":\"Lifecycle role\",\"enabled\":false}")
                    .when().post("/v1/roles")
                    .then().statusCode(201)
                    .body("data.code", is(roleCode))
                    .body("data.enabled", is(false))
                    .extract().path("data.id");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"name\":\"Lifecycle role updated\",\"enabled\":true}")
                    .when().put("/v1/roles/" + roleId)
                    .then().statusCode(200)
                    .body("data.name", is("Lifecycle role updated"))
                    .body("data.enabled", is(true));

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"permissions\":[\"user:read\"]}")
                    .when().put("/v1/roles/" + roleId + "/permissions")
                    .then().statusCode(200)
                    .body("data.updated", is(true));

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles/" + roleId)
                    .then().statusCode(200)
                    .body("data.deleted", is(true));
            roleId = null;
        } finally {
            if (roleId != null) {
                given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
            }
        }
    }

    @Test
    void administratorCanAssignAndRevokeRoleUsers() {
        String admin = login("admin", "password");
        String roleId = null;
        String userId = null;
        try {
            String roleCode = "HTTP_ROLE_" + System.nanoTime();
            roleId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + roleCode + "\",\"name\":\"HTTP role members\"}")
                    .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");
            userId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"role_member_" + System.nanoTime() + "\",\"password\":\"password\",\"displayName\":\"Role member\",\"roleCodes\":[\"USER\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\",\"not-a-uuid\"]}")
                    .when().put("/v1/roles/" + roleId + "/users")
                    .then().statusCode(422);
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\",\"" + UUID.randomUUID() + "\"]}")
                    .when().put("/v1/roles/" + roleId + "/users")
                    .then().statusCode(404);
            List<String> afterRejectedBatch = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + roleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            org.junit.jupiter.api.Assertions.assertFalse(afterRejectedBatch.contains(userId));

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\",\"" + userId + "\"]}")
                    .when().put("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).body("data.updated", is(true));
            List<String> allocated = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + roleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            org.junit.jupiter.api.Assertions.assertEquals(List.of(userId), allocated);

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + userId + "\"]}")
                    .when().delete("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).body("data.updated", is(true));
            List<String> afterRevoke = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + roleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            org.junit.jupiter.api.Assertions.assertFalse(afterRevoke.contains(userId));
        } finally {
            if (userId != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
            }
            if (roleId != null) {
                given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
            }
        }
    }

    /** 验证 role:read 主体可读取最小身份字段，旧 ID 响应和其他权限边界保持不变。 */
    @Test
    void roleReaderCanRequestMinimalMemberIdentityWithoutUserRead() {
        String admin = login("admin", "password");
        String roleCode = "HTTP_ROLE_IDENTITY_" + System.nanoTime();
        String noReadRoleCode = "HTTP_ROLE_NO_READ_" + System.nanoTime();
        String roleId = null;
        String noReadRoleId = null;
        String firstUserId = null;
        String secondUserId = null;
        String candidateUserId = null;
        String blockedUserId = null;
        String firstUsername = "identity_member_a_" + System.nanoTime();
        String secondUsername = "identity_member_b_" + System.nanoTime();
        String candidateUsername = "identity_candidate_" + System.nanoTime();
        String blockedUsername = "identity_blocked_" + System.nanoTime();

        try {
            roleId = createRole(admin, roleCode);
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"permissions\":[\"role:read\"]}")
                    .when().put("/v1/roles/" + roleId + "/permissions")
                    .then().statusCode(200).body("data.updated", is(true));

            firstUserId = createRoleMember(admin, firstUsername, "Member A", "member-a@example.test",
                    "13800000001", roleCode);
            secondUserId = createRoleMember(admin, secondUsername, "Member B", "member-b@example.test",
                    "13800000002", roleCode);
            candidateUserId = createRoleMember(admin, candidateUsername, "Available member",
                    "candidate@example.test", "13900000001", "USER");

            List<String> rolePermissions = given().auth().oauth2(admin)
                    .queryParam("keyword", roleCode)
                    .when().get("/v1/roles")
                    .then().statusCode(200)
                    .extract().path("data.items[0].permissions");
            assertEquals(List.of("role:read"), rolePermissions);

            String readerToken = login(firstUsername, "password");
            List<String> expectedMemberIds = List.of(firstUserId, secondUserId).stream()
                    .sorted(Comparator.reverseOrder())
                    .toList();

            List<String> legacyIds = given().auth().oauth2(readerToken)
                    .queryParam("allocated", true)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .extract().path("data");
            assertEquals(expectedMemberIds, legacyIds);

            List<Map<String, Object>> identityMembers = given().auth().oauth2(readerToken)
                    .queryParam("allocated", true)
                    .queryParam("include", "identity")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .extract().jsonPath().getList("data");

            assertEquals(expectedMemberIds,
                    identityMembers.stream().map(member -> member.get("id")).toList());
            assertEquals(Set.of("id", "username", "displayName"), identityMembers.get(0).keySet());
            assertEquals(firstUsername, identityMembers.stream()
                    .filter(member -> firstUsername.equals(member.get("username")))
                    .findFirst().orElseThrow().get("username"));
            assertEquals("Member A", identityMembers.stream()
                    .filter(member -> firstUsername.equals(member.get("username")))
                    .findFirst().orElseThrow().get("displayName"));

            List<Map<String, Object>> filteredMembers = given().auth().oauth2(readerToken)
                    .queryParam("allocated", true)
                    .queryParam("include", "identity")
                    .queryParam("username", firstUsername.toUpperCase())
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .extract().jsonPath().getList("data");
            assertEquals(1, filteredMembers.size());
            assertEquals(firstUserId, filteredMembers.get(0).get("id"));
            assertEquals(Set.of("id", "username", "displayName"), filteredMembers.get(0).keySet());

            List<Map<String, Object>> unallocatedMembers = given().auth().oauth2(readerToken)
                    .queryParam("allocated", false)
                    .queryParam("include", "identity")
                    .queryParam("phoneNumber", "13900000001")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200)
                    .extract().jsonPath().getList("data");
            assertEquals(1, unallocatedMembers.size());
            assertEquals(candidateUserId, unallocatedMembers.get(0).get("id"));
            assertEquals(candidateUsername, unallocatedMembers.get(0).get("username"));
            assertEquals("Available member", unallocatedMembers.get(0).get("displayName"));
            assertEquals(Set.of("id", "username", "displayName"), unallocatedMembers.get(0).keySet());

            noReadRoleId = createRole(admin, noReadRoleCode);
            blockedUserId = createRoleMember(admin, blockedUsername, "Blocked member",
                    "blocked@example.test", "13900000002", noReadRoleCode);
            String blockedToken = login(blockedUsername, "password");
            given().auth().oauth2(blockedToken)
                    .queryParam("include", "identity")
                    .when().get("/v1/roles/" + noReadRoleId + "/users")
                    .then().statusCode(403);
        } finally {
            if (firstUserId != null) deleteUser(admin, firstUserId);
            if (secondUserId != null) deleteUser(admin, secondUserId);
            if (candidateUserId != null) deleteUser(admin, candidateUserId);
            if (blockedUserId != null) deleteUser(admin, blockedUserId);
            if (roleId != null) deleteRole(admin, roleId);
            if (noReadRoleId != null) deleteRole(admin, noReadRoleId);
        }
    }

    /** 通过真实 HTTP 验证角色成员的大小写、包含筛选、空白处理和 UUID 降序。 */
    @Test
    void administratorCanFilterRoleMembersLikePhoenix() {
        String admin = login("admin", "password");
        String roleId = createRole(admin, "HTTP_ROLE_USER_FILTER_" + System.nanoTime());
        String firstUserId = null;
        String secondUserId = null;
        String suffix = Long.toString(System.nanoTime());
        String firstUsername = "role_member_" + suffix;
        String secondUsername = "roleXmember_" + suffix;

        try {
            firstUserId = createRoleMember(admin, firstUsername, "Alpha-138000");
            secondUserId = createRoleMember(admin, secondUsername, "Beta-139000");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + firstUserId + "\",\"" + secondUserId + "\"]}")
                    .when().put("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).body("data.updated", is(true));

            List<String> expectedDescending = List.of(firstUserId, secondUserId).stream()
                    .sorted(Comparator.reverseOrder())
                    .toList();

            List<String> usernameMatches = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("username", "ROLE%MEMBER")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(expectedDescending, usernameMatches);

            List<String> underscoreWildcardMatches = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("username", "role_member")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(expectedDescending, underscoreWildcardMatches);

            List<String> phoneMatches = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("phoneNumber", "ALPHA-138")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(List.of(firstUserId), phoneMatches);

            List<String> combinedMatches = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("username", "ROLE%MEMBER")
                    .queryParam("phoneNumber", "ALPHA-138")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(List.of(firstUserId), combinedMatches);

            List<String> blankFilters = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("username", "  ")
                    .queryParam("phoneNumber", "")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(expectedDescending, blankFilters);

            List<String> noMatches = given().auth().oauth2(admin)
                    .queryParam("allocated", true)
                    .queryParam("username", "missing-user")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertTrue(noMatches.isEmpty());

            List<String> unallocatedMatches = given().auth().oauth2(admin)
                    .queryParam("allocated", false)
                    .queryParam("username", "ROLE%MEMBER_" + suffix)
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertTrue(unallocatedMatches.isEmpty());

            // 撤销第二名用户后，验证 allocated=false 能按电话筛选返回该用户。
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"userIds\":[\"" + secondUserId + "\"]}")
                    .when().delete("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).body("data.updated", is(true));

            List<String> positiveUnallocatedMatches = given().auth().oauth2(admin)
                    .queryParam("allocated", false)
                    .queryParam("phoneNumber", "BETA-139")
                    .when().get("/v1/roles/" + roleId + "/users")
                    .then().statusCode(200).extract().path("data");
            assertEquals(List.of(secondUserId), positiveUnallocatedMatches);
        } finally {
            if (firstUserId != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + firstUserId).then().statusCode(200);
            }
            if (secondUserId != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + secondUserId).then().statusCode(200);
            }
            given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
        }
    }

    @Test
    void administratorBatchRoleDeleteRollsBackMissingTargetAndDeduplicatesIds() {
        String admin = login("admin", "password");
        String firstId = null;
        String secondId = null;
        try {
            firstId = createRole(admin, "HTTP_ROLE_BATCH_ONE_" + System.nanoTime());
            secondId = createRole(admin, "HTTP_ROLE_BATCH_TWO_" + System.nanoTime());
            String missing = UUID.randomUUID().toString();

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles?ids=" + firstId + "," + missing + "," + secondId)
                    .then().statusCode(404);
            List<String> afterRejected = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            assertTrue(afterRejected.contains(firstId));
            assertTrue(afterRejected.contains(secondId));

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles?ids=" + firstId + "," + firstId + "," + secondId)
                    .then().statusCode(200)
                    .body("data.deleted", is(2));
            List<String> afterSuccessfulDelete = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            assertFalse(afterSuccessfulDelete.contains(firstId));
            assertFalse(afterSuccessfulDelete.contains(secondId));
            firstId = null;
            secondId = null;
        } finally {
            if (firstId != null) given().auth().oauth2(admin).when().delete("/v1/roles/" + firstId);
            if (secondId != null) given().auth().oauth2(admin).when().delete("/v1/roles/" + secondId);
        }
    }

    /** 真实 HTTP 删除单个有成员角色时必须返回冲突，并保留角色和成员关联。 */
    @Test
    void administratorCannotDeleteRoleWithAssignedUser() {
        String admin = login("admin", "password");
        String roleCode = "HTTP_ROLE_IN_USE_SINGLE_" + System.nanoTime();
        String roleId = null;
        String userId = null;
        try {
            roleId = createRole(admin, roleCode);
            userId = createRoleMember(admin, "role_in_use_single_" + System.nanoTime(),
                    "Role in use", "role-in-use-single@example.test", "13800000101", roleCode);

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles/" + roleId)
                    .then().statusCode(422)
                    .body("error.code", is("resource_conflict"));

            List<String> roleIds = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            List<String> memberIds = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + roleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            assertTrue(roleIds.contains(roleId));
            assertTrue(memberIds.contains(userId));
        } finally {
            if (userId != null) deleteUser(admin, userId);
            deleteRoleIfPresent(admin, roleId);
        }
    }

    /** 混合批次含有成员角色时必须整体拒绝，不能删除批次中的空角色。 */
    @Test
    void administratorBatchRoleDeleteRejectsAssignedRoleWithoutPartialDeletion() {
        String admin = login("admin", "password");
        String emptyRoleId = null;
        String assignedRoleId = null;
        String userId = null;
        try {
            emptyRoleId = createRole(admin, "HTTP_ROLE_BATCH_EMPTY_" + System.nanoTime());
            String assignedRoleCode = "HTTP_ROLE_BATCH_IN_USE_" + System.nanoTime();
            assignedRoleId = createRole(admin, assignedRoleCode);
            userId = createRoleMember(admin, "role_in_use_batch_" + System.nanoTime(),
                    "Role in use batch", "role-in-use-batch@example.test", "13800000102", assignedRoleCode);

            given().auth().oauth2(admin)
                    .when().delete("/v1/roles?ids=" + emptyRoleId + "," + assignedRoleId)
                    .then().statusCode(422)
                    .body("error.code", is("resource_conflict"));

            List<String> roleIds = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            List<String> memberIds = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + assignedRoleId + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            assertTrue(roleIds.contains(emptyRoleId));
            assertTrue(roleIds.contains(assignedRoleId));
            assertTrue(memberIds.contains(userId));
        } finally {
            if (userId != null) deleteUser(admin, userId);
            deleteRoleIfPresent(admin, emptyRoleId);
            deleteRoleIfPresent(admin, assignedRoleId);
        }
    }

    /** 单项删除内置 ADMIN 必须返回与 Phoenix 相同的保护错误，且不改管理员成员绑定。 */
    @Test
    void administratorCannotDeleteBuiltInAdminRole() {
        String admin = login("admin", "password");

        given().auth().oauth2(admin)
                .when().delete("/v1/roles/" + SYSTEM_ADMIN_ROLE_ID)
                .then().statusCode(422)
                .body("error.code", is("resource_conflict"))
                .body("message", is("管理员角色不能删除"));

        List<String> memberIds = given().auth().oauth2(admin)
                .when().get("/v1/roles/" + SYSTEM_ADMIN_ROLE_ID + "/users?allocated=true")
                .then().statusCode(200).extract().path("data");
        assertTrue(memberIds.contains("5faed4bb-63af-5158-bd3c-1200c539cfd9"));
    }

    /** 混合批次包含内置 ADMIN 时整体拒绝，并保留普通角色和管理员成员绑定。 */
    @Test
    void administratorBatchDeleteRejectsBuiltInAdminWithoutPartialDeletion() {
        String admin = login("admin", "password");
        String ordinaryRoleId = createRole(admin, "HTTP_ROLE_WITH_ADMIN_BATCH_" + System.nanoTime());
        try {
            given().auth().oauth2(admin)
                    .when().delete("/v1/roles?ids=" + ordinaryRoleId + "," + SYSTEM_ADMIN_ROLE_ID)
                    .then().statusCode(422)
                    .body("error.code", is("resource_conflict"))
                    .body("message", is("管理员角色不能删除"));

            List<String> roleIds = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            List<String> adminMemberIds = given().auth().oauth2(admin)
                    .when().get("/v1/roles/" + SYSTEM_ADMIN_ROLE_ID + "/users?allocated=true")
                    .then().statusCode(200).extract().path("data");
            assertTrue(roleIds.contains(ordinaryRoleId));
            assertTrue(roleIds.contains(SYSTEM_ADMIN_ROLE_ID));
            assertTrue(adminMemberIds.contains("5faed4bb-63af-5158-bd3c-1200c539cfd9"));
        } finally {
            deleteRoleIfPresent(admin, ordinaryRoleId);
        }
    }

    /** 验证角色列表在兼容旧数组响应的同时支持服务端分页、关键字和状态筛选。 */
    @Test
    void administratorCanPageAndFilterRoles() {
        String admin = login("admin", "password");
        String roleId = null;
        String roleCode = "HTTP_ROLE_PAGE_" + System.nanoTime();
        String roleName = "Role pagination " + System.nanoTime();
        try {
            roleId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"" + roleCode + "\",\"name\":\"" + roleName + "\",\"enabled\":false}")
                    .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");

            List<String> legacy = given().auth().oauth2(admin)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.id");
            assertTrue(legacy.contains(roleId));

            given().auth().oauth2(admin)
                    .when().get("/v1/roles?page=1&size=1")
                    .then().statusCode(200)
                    .body("data.page", is(1))
                    .body("data.size", is(1))
                    .body("data.items.size()", is(1))
                    .body("data.total", greaterThanOrEqualTo(1));

            given().auth().oauth2(admin)
                    .when().get("/v1/roles?keyword=" + roleCode.toLowerCase())
                    .then().statusCode(200)
                    .body("data.items.size()", is(1))
                    .body("data.items[0].id", is(roleId))
                    .body("data.items[0].code", is(roleCode));

            given().auth().oauth2(admin).queryParam("keyword", roleName)
                    .when().get("/v1/roles")
                    .then().statusCode(200)
                    .body("data.items.size()", is(1))
                    .body("data.items[0].id", is(roleId));

            List<Boolean> disabled = given().auth().oauth2(admin)
                    .when().get("/v1/roles?status=disabled")
                    .then().statusCode(200).extract().path("data.items.enabled");
            assertFalse(disabled.isEmpty());
            assertTrue(disabled.stream().allMatch(value -> !value));
            assertEquals(Boolean.FALSE, given().auth().oauth2(admin)
                    .when().get("/v1/roles?status=0&keyword=" + roleCode)
                    .then().statusCode(200).extract().path("data.items[0].enabled"));
        } finally {
            if (roleId != null) {
                given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
            }
        }
    }

    private static String createRole(String admin, String code) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"HTTP batch role\"}")
                .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");
    }

    private static String createRoleMember(String admin, String username, String phoneNumber) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Role member\",\"phoneNumber\":\"" + phoneNumber + "\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
    }

    /** 创建具备指定角色的测试用户，并写入敏感字段用于检查响应投影。 */
    private static String createRoleMember(String admin, String username, String displayName,
                                           String email, String phoneNumber, String roleCode) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body(Map.of(
                        "username", username,
                        "password", "password",
                        "displayName", displayName,
                        "email", email,
                        "phoneNumber", phoneNumber,
                        "roleCodes", List.of(roleCode)))
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
    }

    /** 使用管理员测试令牌删除当前测试创建的账号。 */
    private static void deleteUser(String admin, String userId) {
        given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
    }

    /** 使用管理员测试令牌删除当前测试创建的角色。 */
    private static void deleteRole(String admin, String roleId) {
        given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
    }

    /** 清理测试创建的角色；角色已被待测请求删除时不再重复请求。 */
    private static void deleteRoleIfPresent(String admin, String roleId) {
        if (roleId == null) return;
        List<String> roleIds = given().auth().oauth2(admin)
                .when().get("/v1/roles")
                .then().statusCode(200).extract().path("data.id");
        if (roleIds != null && roleIds.contains(roleId)) deleteRole(admin, roleId);
    }

    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
