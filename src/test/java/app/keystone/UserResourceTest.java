package app.keystone;

import app.keystone.auth.TotpService;
import app.keystone.auth.MfaService;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.zip.ZipInputStream;

@QuarkusTest
class UserResourceTest extends AuthTestFixture {
    @jakarta.inject.Inject MfaService mfaService;
    private static final String PROFILE_PASSWORD = "Profile-Changed-123!";

    @Test
    void profileDisplayNameFailuresHaveDedicatedCode() {
        String admin = login("admin", "password");
        // 缺失、null 和空白输入都指向同一展示名必填条件，不修改原资料。
        String original = given().auth().oauth2(admin).when().get("/v1/profile")
                .then().statusCode(200).extract().path("data.displayName");
        for (String body : java.util.List.of("{}", "{\"displayName\":null}", "{\"displayName\":\"  \"}")) {
            given().auth().oauth2(admin).contentType(JSON).body(body).when().put("/v1/profile")
                    .then().statusCode(422).body("error.code", is("profile_display_name_required"));
        }
        given().auth().oauth2(admin).when().get("/v1/profile")
                .then().statusCode(200).body("data.displayName", is(original));
    }

    @Test
    void profileUpdateWithInvalidFieldTypeUsesValidationFailedCode() {
        String admin = login("admin", "password");
        String original = given().auth().oauth2(admin).when().get("/v1/profile")
                .then().statusCode(200).extract().path("data.displayName");

        // 字段类型错误属于请求校验失败，不能误报为展示名缺失。
        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"displayName\":\"Changed name\",\"sex\":{}}")
                .when().put("/v1/profile").then().statusCode(422)
                .body("error.code", is("validation_failed"));

        given().auth().oauth2(admin).when().get("/v1/profile")
                .then().statusCode(200).body("data.displayName", is(original));
    }

    @Test
    void profileAvatarFailuresHaveDedicatedCode() {
        String admin = login("admin", "password");
        String avatar = "/profile/avatar/codex-avatar-test.png";
        given().auth().oauth2(admin).contentType(JSON).body(java.util.Map.of("avatar", avatar))
                .when().put("/v1/profile/avatar").then().statusCode(200);
        // 缺失、null 和空白都不能覆盖已保存的头像。
        for (String body : java.util.List.of("{}", "{\"avatar\":null}", "{\"avatar\":\"  \"}")) {
            given().auth().oauth2(admin).contentType(JSON).body(body).when().put("/v1/profile/avatar")
                    .then().statusCode(422).body("error.code", is("profile_avatar_required"));
        }
        given().auth().oauth2(admin).when().get("/v1/profile")
                .then().statusCode(200).body("data.avatar", is(avatar));
    }

    @Test
    void profileUpdateClearsExplicitNullFieldsAndPreservesOmittedFields() {
        String admin = login("admin", "password");
        String username = "nullable_profile_" + System.nanoTime();
        String userId = null;
        try {
            userId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Nullable profile\",\"email\":\"profile@example.test\",\"phoneNumber\":\"13800000000\",\"sex\":1,\"avatar\":\"/profile/avatar/null-update.png\",\"roleCodes\":[\"ADMIN\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
            String accessToken = login(username, "password");

            given().auth().oauth2(accessToken).contentType(JSON)
                    .body("{\"displayName\":\"Nullable profile\"}")
                    .when().put("/v1/profile").then().statusCode(200)
                    .body("data.email", is("profile@example.test"))
                    .body("data.phoneNumber", is("13800000000"))
                    .body("data.sex", is(1))
                    .body("data.avatar", is("/profile/avatar/null-update.png"));

            // 与 admin-web 一样，显式 null 清空字段；未提交字段继续保留。
            given().auth().oauth2(accessToken).contentType(JSON)
                    .body("{\"displayName\":\"Nullable profile\",\"email\":null,\"phoneNumber\":null,\"sex\":null,\"avatar\":null}")
                    .when().put("/v1/profile").then().statusCode(200)
                    .body("data.email", org.hamcrest.Matchers.nullValue())
                    .body("data.phoneNumber", org.hamcrest.Matchers.nullValue())
                    .body("data.sex", org.hamcrest.Matchers.nullValue())
                    .body("data.avatar", org.hamcrest.Matchers.nullValue());
        } finally {
            deleteTemporaryUser(admin, userId);
        }
    }

    @Test
    void administratorCanCreateDisabledUserFromTheRequestedStatus() {
        String admin = login("admin", "password");
        String id = null;
        try {
            id = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"disabled_create_" + System.nanoTime() + "\",\"password\":\"password\",\"displayName\":\"Disabled create\",\"enabled\":false,\"roleCodes\":[\"USER\"]}")
                    .when().post("/v1/users")
                    .then().statusCode(201)
                    .body("data.enabled", is(false))
                    .extract().path("data.id");
        } finally {
            if (id != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
            }
        }
    }

    @Test
    void adminCanFilterAndUpdateProfileFieldsButRegularUsersOnlySeeTheirOwnRecord() {
        String admin = login("admin", "password");
        String username = "profile_" + System.nanoTime();
        String peerUsername = "profile_peer_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Profile User\",\"email\":\"old@example.test\",\"phoneNumber\":\"13800000000\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).body("data.email", is("old@example.test")).extract().path("data.id");
        String peerId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + peerUsername + "\",\"password\":\"password\",\"displayName\":\"Peer User\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

        given().auth().oauth2(admin).when().get("/v1/users?username=" + username).then().statusCode(200).body("data.items", not(empty()));
        String user = login(username, "password");
        given().auth().oauth2(user).when().get("/v1/users").then().statusCode(200)
                .body("data.items.size()", is(1))
                .body("data.items[0].username", is(username));
        given().auth().oauth2(user).when().get("/v1/users/" + peerId).then().statusCode(404);
        given().auth().oauth2(user).contentType(JSON)
                .body("{\"displayName\":\"Updated User\",\"email\":\"new@example.test\",\"phoneNumber\":\"13900000000\",\"sex\":1}")
                .when().put("/v1/profile").then().statusCode(200).body("data.email", is("new@example.test"));
        given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
        given().auth().oauth2(admin).when().delete("/v1/users/" + peerId).then().statusCode(200);
    }

    @Test
    void userUpdateClearsExplicitNullFieldsAndPreservesOmittedFields() {
        String admin = login("admin", "password");
        String username = "nullable_update_" + System.nanoTime();
        String postId = null;
        String userId = null;
        try {
            postId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"code\":\"NULLABLE_POST_" + System.nanoTime() + "\",\"name\":\"Nullable post\",\"sortOrder\":1,\"enabled\":true}")
                    .when().post("/v1/posts").then().statusCode(201).extract().path("data.id");
            userId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Nullable user\",\"postId\":\"" + postId + "\",\"email\":\"old@example.test\",\"phoneNumber\":\"13800000000\",\"remark\":\"keep or clear\",\"roleCodes\":[\"USER\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

            // 缺少字段不改变现值；显式 null 表示用户确认清空该字段。
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"displayName\":\"Nullable user\",\"enabled\":true,\"clearDept\":false,\"roleCodes\":null}")
                    .when().put("/v1/users/" + userId).then().statusCode(200)
                    .body("data.postId", is(postId))
                    .body("data.email", is("old@example.test"))
                    .body("data.phoneNumber", is("13800000000"))
                    .body("data.remark", is("keep or clear"));

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"displayName\":\"Nullable user\",\"postId\":null,\"email\":null,\"phoneNumber\":null,\"remark\":null,\"enabled\":true,\"clearDept\":false,\"roleCodes\":null}")
                    .when().put("/v1/users/" + userId).then().statusCode(200)
                    .body("data.postId", org.hamcrest.Matchers.nullValue())
                    .body("data.email", org.hamcrest.Matchers.nullValue())
                    .body("data.phoneNumber", org.hamcrest.Matchers.nullValue())
                    .body("data.remark", org.hamcrest.Matchers.nullValue());
        } finally {
            deleteTemporaryUser(admin, userId);
            if (postId != null) given().auth().oauth2(admin).when().delete("/v1/posts/" + postId).then().statusCode(200);
        }
    }

    @Test
    void changingUserRolesInvalidatesExistingAccessToken() {
        String admin = login("admin", "password");
        String username = "permission_version_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Version User\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        String user = login(username, "password");
        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"roleCodes\":[\"USER\"]}")
                .when().put("/v1/users/" + id).then().statusCode(200);
        given().auth().oauth2(user).when().get("/v1/profile").then().statusCode(401);
        given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
    }

    @Test
    void adminCanExportUsersAsScopedExcelWithoutSecrets() {
        String admin = login("admin", "password");
        String username = "export_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Export User\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

        byte[] workbook = given().auth().oauth2(admin)
                .when().get("/v1/users/export?username=" + username)
                .then().statusCode(200).contentType(containsString("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
                .extract().asByteArray();

        org.junit.jupiter.api.Assertions.assertEquals((byte) 'P', workbook[0]);
        org.junit.jupiter.api.Assertions.assertEquals((byte) 'K', workbook[1]);
        String sheet = readWorksheet(workbook);
        org.junit.jupiter.api.Assertions.assertTrue(sheet.contains(username));
        org.junit.jupiter.api.Assertions.assertTrue(sheet.contains("Export User"));
        org.junit.jupiter.api.Assertions.assertFalse(sheet.contains("password_hash"));
        org.junit.jupiter.api.Assertions.assertFalse(sheet.contains("password"));
        given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
    }

    @Test
    void userImportRejectsAal1EvenWhenMfaPolicyIsDisabled() {
        String admin = login("admin", "password");
        String username = "import_" + System.nanoTime();
        byte[] workbook = ExcelExporter.export(
                java.util.List.of("部门ID", "用户名", "昵称", "密码", "状态"),
                java.util.List.of(
                        java.util.List.of("", username, "导入用户", "password", true),
                        java.util.List.of("", username + "_invalid", "缺少密码", "", true)));

        given().auth().oauth2(admin)
                .multiPart("file", "users.xlsx", workbook,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                .when().post("/v1/users/import")
                .then().statusCode(403)
                .body("error.code", is("mfa_step_up_required"));
    }

    // 未启用强制 MFA 时，个人改密应成功、撤销旧会话，并允许新密码登录。
    @Test
    void profilePasswordChangeSucceedsWithoutRequiredMfaAndRevokesTheOldSession() {
        String admin = login("admin", "password");
        String username = "profile_password_" + System.nanoTime();
        String userId = null;
        try {
            userId = createTemporaryAdmin(admin, username);
            String oldAccessToken = login(username, "password");

            given().auth().oauth2(oldAccessToken).contentType(JSON)
                    .body("{\"password\":\"" + PROFILE_PASSWORD + "\"}")
                    .when().put("/v1/profile/password")
                    .then().statusCode(200)
                    .body("data.updated", is(true));

            given().auth().oauth2(oldAccessToken)
                    .when().get("/v1/profile")
                    .then().statusCode(401);

            String newAccessToken = login(username, PROFILE_PASSWORD);
            given().auth().oauth2(newAccessToken)
                    .when().get("/v1/profile")
                    .then().statusCode(200)
                    .body("data.username", is(username));
        } finally {
            deleteTemporaryUser(admin, userId);
        }
    }

    // 启用 MFA 策略后，AAL1 改密请求应被拒绝，且拒绝时密码仍保持不变。
    @Test
    void profilePasswordChangeRequiresStepUpWhenAccountMfaPolicyIsEnabled() throws Exception {
        String admin = login("admin", "password");
        String username = "profile_password_mfa_" + System.nanoTime();
        String userId = null;
        try {
            userId = createTemporaryAdmin(admin, username);
            String accessToken = login(username, "password");
            var enrollment = given().auth().oauth2(accessToken)
                    .contentType(JSON)
                    .when().post("/v1/auth/mfa/enroll")
                    .then().statusCode(201).extract();
            String enrollmentCode = new TotpService().code(enrollment.path("data.secret"), Instant.now());
            given().auth().oauth2(accessToken).contentType(JSON)
                    .body("{\"challengeId\":\"" + enrollment.path("data.challengeId")
                            + "\",\"code\":\"" + enrollmentCode + "\"}")
                    .when().post("/v1/auth/mfa/enroll/verify")
                    .then().statusCode(200);
            assertTrue(mfaService.setRequired(userId, true));

            String passwordHashBefore = readPasswordHash(username);
            given().auth().oauth2(accessToken).contentType(JSON)
                    .body("{\"password\":\"" + PROFILE_PASSWORD + "\"}")
                    .when().put("/v1/profile/password")
                    .then().statusCode(403)
                    .body("error.code", is("mfa_step_up_required"));

            String passwordHashAfter = readPasswordHash(username);
            assertTrue(MessageDigest.isEqual(passwordHashBefore.getBytes(StandardCharsets.UTF_8),
                    passwordHashAfter.getBytes(StandardCharsets.UTF_8)));
            assertTrue(io.quarkus.elytron.security.common.BcryptUtil.matches("password", passwordHashAfter));
            assertFalse(io.quarkus.elytron.security.common.BcryptUtil.matches(PROFILE_PASSWORD, passwordHashAfter));
            given().auth().oauth2(accessToken)
                    .when().get("/v1/profile")
                    .then().statusCode(200);
        } finally {
            deleteTemporaryUser(admin, userId);
        }
    }

    @Test
    void userImportSucceedsWithAal2AndReportsPerRowResult() throws Exception {
        String admin = login("admin", "password");
        String username = "import_aal2_admin_" + System.nanoTime();
        String importedUsername = "imported_aal2_" + System.nanoTime();
        String disabledUsername = importedUsername + "_disabled";
        String defaultEnabledUsername = importedUsername + "_default";
        String disallowedUsername = importedUsername + "_disallowed";
        String foreignKeyUsername = importedUsername + "_invalid_post";
        String legacyPunctuationUsername = importedUsername + "-legacy";
        String missingPostId = java.util.UUID.randomUUID().toString();
        String temporaryAdminId = null;
        try {
            temporaryAdminId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"AAL2 Import Admin\",\"roleCodes\":[\"ADMIN\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

            String aal1 = login(username, "password");
            var enrollment = given().auth().oauth2(aal1).contentType(JSON)
                    .when().post("/v1/auth/mfa/enroll").then().statusCode(201).extract();
            String enrollmentCode = new TotpService().code(enrollment.path("data.secret"), Instant.now());
            var enrollmentResult = given().auth().oauth2(aal1).contentType(JSON)
                    .body("{\"challengeId\":\"" + enrollment.path("data.challengeId") + "\",\"code\":\"" + enrollmentCode + "\"}")
                    .when().post("/v1/auth/mfa/enroll/verify").then().statusCode(200).extract();

            String recoveryCode = enrollmentResult.path("data.recoveryCodes[0]");
            given().auth().oauth2(aal1).contentType(JSON)
                    .body("{\"required\":true}")
                    .when().put("/v1/auth/mfa/policy/" + temporaryAdminId).then().statusCode(200);

            var loginChallenge = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                    .when().post("/v1/auth/login").then().statusCode(401)
                    .body("message", is("MFA_REQUIRED"))
                    .extract();
            var aal2Login = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"challengeId\":\"" + loginChallenge.path("data.challengeId")
                            + "\",\"code\":\"" + recoveryCode + "\",\"forceLogin\":true}")
                    .when().post("/v1/auth/mfa/verify").then().statusCode(200).extract();
            String aal2 = aal2Login.path("data.accessToken");
            String payload = new String(java.util.Base64.getUrlDecoder().decode(aal2.split("\\.")[1]), StandardCharsets.UTF_8);
            var claims = new com.fasterxml.jackson.databind.ObjectMapper().readTree(payload);
            org.junit.jupiter.api.Assertions.assertEquals("AAL2", claims.path("aal").asText());
            org.junit.jupiter.api.Assertions.assertEquals("recovery", claims.path("amr").get(0).asText());

            // 用户创建接口继续使用原有 HTTP 422 和通用校验码。
            given().auth().oauth2(aal2).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"Strong!123\",\"displayName\":\"Duplicate\",\"roleCodes\":[\"USER\"]}")
                    .when().post("/v1/users").then().statusCode(422)
                    .body("error.code", is("validation_failed"));
            given().auth().oauth2(aal2).contentType(JSON)
                    .body("{\"username\":\"" + foreignKeyUsername + "\",\"password\":\"Strong!123\",\"displayName\":\"Missing post\",\"postId\":\"" + missingPostId + "\",\"roleCodes\":[\"USER\"]}")
                    .when().post("/v1/users").then().statusCode(422)
                    .body("error.code", is("validation_failed"));

            // 验证导入保留禁用状态、缺省状态，并继续逐行报告无效记录。
            byte[] workbook = ExcelExporter.export(
                    java.util.List.of("部门ID", "用户名", "昵称", "密码", "状态", "职位ID"),
                    java.util.List.of(
                            java.util.List.of("", disabledUsername, "AAL2 禁用用户", "password", false, ""),
                            java.util.List.of("", defaultEnabledUsername, "AAL2 默认启用用户", "password", "", ""),
                            java.util.List.of("", importedUsername + "_invalid", "缺少密码", "", true, ""),
                            java.util.List.of("", username, "重复 AAL2 管理员", "password", true, ""),
                            java.util.List.of("", foreignKeyUsername, "缺少岗位", "password", true, missingPostId),
                            java.util.List.of("", disallowedUsername, "禁止密码", "test-only-disallowed", true, ""),
                            java.util.List.of("", legacyPunctuationUsername, "保留旧用户名格式", "password", true, "")));

            given().auth().oauth2(aal2)
                    .multiPart("file", "users.xlsx", workbook,
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    .when().post("/v1/users/import")
                    .then().statusCode(200)
                    .body("data.total", is(7))
                    .body("data.success", is(3))
                    .body("data.failed.size()", is(4))
                    .body("data.failed[0].row", is(4))
                    .body("data.failed[0].username", is(importedUsername + "_invalid"))
                    .body("data.failed[0].reason", is("password does not meet security policy"))
                    .body("data.failed[0].code", is("password_required"))
                    .body("data.failed[1].row", is(5))
                    .body("data.failed[1].username", is(username))
                    .body("data.failed[1].reason", is("username already exists"))
                    .body("data.failed[1].code", is("username_already_exists"))
                    .body("data.failed[2].row", is(6))
                    .body("data.failed[2].username", is(foreignKeyUsername))
                    .body("data.failed[2].reason", is("username already exists"))
                    .body("data.failed[2].code", is("validation_failed"))
                    .body("data.failed[2].code", not(is("username_already_exists")))
                    .body("data.failed[3].row", is(7))
                    .body("data.failed[3].username", is(disallowedUsername))
                    .body("data.failed[3].reason", is("password does not meet security policy"))
                    .body("data.failed[3].code", is("password_disallowed"));

            var disabledUser = given().auth().oauth2(aal2).when().get("/v1/users?username=" + disabledUsername)
                    .then().statusCode(200).extract();
            org.junit.jupiter.api.Assertions.assertEquals(1, (int) disabledUser.path("data.items.size()"));
            assertFalse((Boolean) disabledUser.path("data.items[0].enabled"));

            given().contentType(JSON)
                    .body("{\"username\":\"" + disabledUsername + "\",\"password\":\"password\"}")
                    .when().post("/v1/auth/login")
                    .then().statusCode(401).body("error.code", is("invalid_credential"));

            var defaultEnabledUser = given().auth().oauth2(aal2)
                    .when().get("/v1/users?username=" + defaultEnabledUsername)
                    .then().statusCode(200).extract();
            org.junit.jupiter.api.Assertions.assertEquals(1, (int) defaultEnabledUser.path("data.items.size()"));
            assertTrue((Boolean) defaultEnabledUser.path("data.items[0].enabled"));
            assertFalse(login(defaultEnabledUsername, "password").isBlank());
            assertFalse(login(legacyPunctuationUsername, "password").isBlank());
        } finally {
            cleanupImportedUser(admin, disabledUsername);
            cleanupImportedUser(admin, defaultEnabledUsername);
            cleanupImportedUser(admin, importedUsername + "_invalid");
            cleanupImportedUser(admin, disallowedUsername);
            cleanupImportedUser(admin, legacyPunctuationUsername);
            if (temporaryAdminId != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + temporaryAdminId).then().statusCode(200);
            }
        }
    }

    @Test
    void mfaSessionConflictKeepsChallengeForExplicitForceLogin() {
        String admin = login("admin", "password");
        String username = "mfa_conflict_" + System.nanoTime();
        String temporaryId = null;
        try {
            temporaryId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"MFA Conflict\",\"roleCodes\":[\"ADMIN\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

            var initial = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                    .when().post("/v1/auth/login").then().statusCode(200).extract();
            String aal1 = initial.path("data.accessToken");
            var enrollment = given().auth().oauth2(aal1).contentType(JSON)
                    .when().post("/v1/auth/mfa/enroll").then().statusCode(201).extract();
            String secret = enrollment.path("data.secret");
            String enrollmentCode = new TotpService().code(secret, Instant.now());
            given().auth().oauth2(aal1).contentType(JSON)
                    .body("{\"challengeId\":\"" + enrollment.path("data.challengeId") + "\",\"code\":\"" + enrollmentCode + "\"}")
                    .when().post("/v1/auth/mfa/enroll/verify").then().statusCode(200);
            org.junit.jupiter.api.Assertions.assertTrue(mfaService.setRequired(temporaryId, true));

            var challenge = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                    .when().post("/v1/auth/login").then().statusCode(401).extract();
            String code = new TotpService().code(secret, Instant.now().plusSeconds(30));
            String verifyBody = "{\"username\":\"" + username + "\",\"challengeId\":\""
                    + challenge.path("data.challengeId") + "\",\"code\":\"" + code + "\"}";
            given().contentType(JSON).body(verifyBody).when().post("/v1/auth/mfa/verify").then().statusCode(409);
            given().contentType(JSON).body(verifyBody.replace("}", ",\"forceLogin\":true}"))
                    .when().post("/v1/auth/mfa/verify").then().statusCode(200)
                    .body("data.accessToken", org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyOrNullString()));
        } finally {
            if (temporaryId != null) given().auth().oauth2(admin).when().delete("/v1/users/" + temporaryId).then().statusCode(200);
        }
    }

    @Test
    void stepUpReturnsIndependentAal2TokenWithoutRefreshState() throws Exception {
        String admin = login("admin", "password");
        String username = "step_up_" + System.nanoTime();
        String temporaryAdminId = null;
        try {
            temporaryAdminId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Step Up Admin\",\"roleCodes\":[\"ADMIN\"]}")
                    .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

            var initialLogin = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                    .when().post("/v1/auth/login").then().statusCode(200).extract();
            String aal1 = initialLogin.path("data.accessToken");
            String refresh = initialLogin.path("data.refreshToken");
            var enrollment = given().auth().oauth2(aal1).contentType(JSON)
                    .when().post("/v1/auth/mfa/enroll").then().statusCode(201).extract();
            String secret = enrollment.path("data.secret");
            String enrollmentCode = new TotpService().code(secret, Instant.now());
            given().auth().oauth2(aal1).contentType(JSON)
                    .body("{\"challengeId\":\"" + enrollment.path("data.challengeId") + "\",\"code\":\"" + enrollmentCode + "\"}")
                    .when().post("/v1/auth/mfa/enroll/verify").then().statusCode(200);

            var stepUpChallenge = given().auth().oauth2(aal1).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(201)
                    .body("data.challengeId", org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyOrNullString()))
                    .body("data.clientId", is("web")).extract();
            org.junit.jupiter.api.Assertions.assertNull(stepUpChallenge.path("data.purpose"));
            org.junit.jupiter.api.Assertions.assertNull(stepUpChallenge.path("data.sessionId"));
            org.junit.jupiter.api.Assertions.assertNull(stepUpChallenge.path("data.contextHash"));
            String stepUpCode = new TotpService().code(secret, Instant.now().plusSeconds(30));
            var stepUp = given().auth().oauth2(aal1).contentType(JSON)
                    .body("{\"challengeId\":\"" + stepUpChallenge.path("data.challengeId") + "\",\"code\":\"" + stepUpCode + "\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(200).extract();

            String aal2 = stepUp.path("data.accessToken");
            org.junit.jupiter.api.Assertions.assertNotNull(aal2);
            org.junit.jupiter.api.Assertions.assertNull(stepUp.path("data.refreshToken"));
            org.junit.jupiter.api.Assertions.assertEquals("AAL2", stepUp.path("data.authenticationLevel"));
            org.junit.jupiter.api.Assertions.assertEquals("otp", stepUp.path("data.amr"));
            var mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            var aal1Claims = mapper.readTree(new String(java.util.Base64.getUrlDecoder().decode(aal1.split("\\.")[1]), StandardCharsets.UTF_8));
            var aal2Claims = mapper.readTree(new String(java.util.Base64.getUrlDecoder().decode(aal2.split("\\.")[1]), StandardCharsets.UTF_8));
            org.junit.jupiter.api.Assertions.assertEquals("AAL2", aal2Claims.path("aal").asText());
            org.junit.jupiter.api.Assertions.assertEquals("otp", aal2Claims.path("amr").get(0).asText());
            org.junit.jupiter.api.Assertions.assertNotEquals(aal1Claims.path("jti").asText(), aal2Claims.path("jti").asText());
            org.junit.jupiter.api.Assertions.assertEquals(aal1Claims.path("sid").asText(), aal2Claims.path("sid").asText());
            org.junit.jupiter.api.Assertions.assertEquals("web", aal2Claims.path("client_id").asText());
            given().auth().oauth2(aal1).when().get("/v1/profile").then().statusCode(401);
            given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                    .when().post("/v1/auth/refresh").then().statusCode(200)
                    .body("data.refreshToken", org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyOrNullString()));
        } finally {
            if (temporaryAdminId != null) {
                given().auth().oauth2(admin).when().delete("/v1/users/" + temporaryAdminId).then().statusCode(200);
            }
        }
    }

    private static String readWorksheet(byte[] workbook) {
        try (var zip = new ZipInputStream(new ByteArrayInputStream(workbook), StandardCharsets.UTF_8)) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                if ("xl/worksheets/sheet1.xml".equals(entry.getName())) return new String(zip.readAllBytes(), StandardCharsets.UTF_8);
            }
            throw new AssertionError("worksheet is missing");
        } catch (java.io.IOException e) {
            throw new AssertionError("invalid Excel workbook", e);
        }
    }

    private static String login(String username, String password) {
        return given().contentType(JSON).body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }

    /** 通过管理接口按唯一用户名清理导入测试创建的用户。 */
    private static void cleanupImportedUser(String admin, String username) {
        java.util.List<String> ids = given().auth().oauth2(admin)
                .when().get("/v1/users?username=" + username)
                .then().statusCode(200)
                .extract().path("data.items.id");
        if (ids == null) return;
        for (String id : ids) {
            given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
        }
    }

    /** 在测试库创建具备个人改密权限的临时管理员，并由各测试在 finally 中清理。 */
    private static String createTemporaryAdmin(String admin, String username) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Profile password test\",\"roleCodes\":[\"ADMIN\"]}")
                .when().post("/v1/users")
                .then().statusCode(201)
                .extract().path("data.id");
    }

    /** 仅比较测试用户当前哈希是否匹配旧密码或新密码，不将哈希写入断言输出。 */
    private String readPasswordHash(String username) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("SELECT password_hash FROM sys_user WHERE username = ?")) {
            statement.setString(1, username);
            try (var result = statement.executeQuery()) {
                if (!result.next()) throw new AssertionError("temporary profile test user is missing");
                return result.getString(1);
            }
        }
    }

    private static void deleteTemporaryUser(String admin, String userId) {
        if (userId != null) {
            given().auth().oauth2(admin)
                    .when().delete("/v1/users/" + userId)
                    .then().statusCode(200);
        }
    }
}
