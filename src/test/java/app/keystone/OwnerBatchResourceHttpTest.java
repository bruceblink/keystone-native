package app.keystone;

import app.keystone.identity.UuidValues;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

/** 通过真实 MySQL HTTP 链路验证公告和任务批量删除的范围及事务边界。 */
@QuarkusTest
class OwnerBatchResourceHttpTest extends AuthTestFixture {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";

    @Inject DataSource dataSource;
    private String ownerRole;
    private String otherRole;
    private String ownerId;
    private String otherId;
    private String ownerToken;
    private String otherToken;
    private String ownerNoticeId;
    private String otherNoticeId;
    private String ownerJobId;
    private String otherJobId;
    private String ownerJobCode;

    @BeforeEach
    void createOwnerScopedSubjects() throws Exception {
        ownerRole = UuidValues.v7();
        otherRole = UuidValues.v7();
        ownerId = UuidValues.v7();
        otherId = UuidValues.v7();
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String ownerName = "batch_owner_" + suffix;
        String otherName = "batch_other_" + suffix;
        try (Connection connection = dataSource.getConnection()) {
            clearLoginRateLimits(connection);
            insertRole(connection, ownerRole, "batch_owner_" + suffix);
            insertRole(connection, otherRole, "batch_other_" + suffix);
            insertUser(connection, ownerId, ownerName);
            insertUser(connection, otherId, otherName);
            insertRolePermissions(connection, ownerRole);
            insertRolePermissions(connection, otherRole);
            insertUserRole(connection, ownerId, ownerRole);
            insertUserRole(connection, otherId, otherRole);
        }
        ownerToken = login(ownerName);
        otherToken = login(otherName);
    }

    @AfterEach
    void removeOwnerScopedSubjects() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            deleteOwnedRecords(connection, ownerId);
            deleteOwnedRecords(connection, otherId);
            deleteUser(connection, ownerId);
            deleteUser(connection, otherId);
            deleteRole(connection, ownerRole);
            deleteRole(connection, otherRole);
        }
    }

    @Test
    void noticeBatchDeleteRejectsMixedOwnersWithoutPartialDelete() {
        ownerNoticeId = createNotice(ownerToken, "批量公告");
        otherNoticeId = createNotice(otherToken, "其他公告");

        given().auth().oauth2(ownerToken)
                .when().delete("/v1/notices?notice_ids=" + ownerNoticeId + "," + otherNoticeId)
                .then().statusCode(404);
        given().auth().oauth2(ownerToken).when().get("/v1/notices/manage")
                .then().statusCode(200).body("data", hasSize(1));
        given().auth().oauth2(otherToken).when().get("/v1/notices/manage")
                .then().statusCode(200).body("data", hasSize(1));

        given().auth().oauth2(ownerToken)
                .when().delete("/v1/notices?notice_ids=not-a-uuid")
                .then().statusCode(422).body("error.code", is("validation_failed"));
        given().auth().oauth2(ownerToken)
                .when().delete("/v1/notices?notice_ids=" + ownerNoticeId + "," + ownerNoticeId)
                .then().statusCode(200).body("data.deleted", is(1));
        ownerNoticeId = null;
    }

    @Test
    void jobBatchDeleteRejectsMixedOwnersAndPreservesExecutionLogs() throws Exception {
        ownerJobCode = code("batch-owner-job");
        ownerJobId = createJob(ownerToken, ownerJobCode);
        otherJobId = createJob(otherToken, code("batch-other-job"));
        given().auth().oauth2(ownerToken).when().post("/v1/jobs/" + ownerJobId + "/run")
                .then().statusCode(200);
        assertJobLogExists(ownerJobCode);

        given().auth().oauth2(ownerToken)
                .when().delete("/v1/jobs?jobIds=" + ownerJobId + "," + otherJobId)
                .then().statusCode(404);
        given().auth().oauth2(ownerToken).when().get("/v1/jobs/" + ownerJobId)
                .then().statusCode(200);
        given().auth().oauth2(otherToken).when().get("/v1/jobs/" + otherJobId)
                .then().statusCode(200);
        given().auth().oauth2(ownerToken)
                .when().delete("/v1/jobs?jobIds=not-a-uuid")
                .then().statusCode(422).body("error.code", is("validation_failed"));

        given().auth().oauth2(ownerToken)
                .when().delete("/v1/jobs?jobIds=" + ownerJobId)
                .then().statusCode(200).body("data.deleted", is(1));
        assertJobLogExists(ownerJobCode);
        ownerJobId = null;
    }

    private String createNotice(String token, String title) {
        return given().auth().oauth2(token).contentType(JSON)
                .body("{\"title\":\"" + title + "\",\"content\":\"批量范围\",\"noticeType\":\"NOTICE\"}")
                .when().post("/v1/notices").then().statusCode(201).extract().path("data.id");
    }

    private String createJob(String token, String code) {
        String body = "{\"code\":\"" + code + "\",\"name\":\"批量任务\",\"cron\":\"0/30 * * * * ?\","
                + "\"invokeTarget\":\"keystoneJob.heartbeat()\",\"concurrent\":false,\"enabled\":false}";
        return given().auth().oauth2(token).contentType(JSON).body(body)
                .when().post("/v1/jobs").then().statusCode(201).extract().path("data.id");
    }

    private String code(String prefix) {
        return prefix + "-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    private String login(String username) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }

    private void assertJobLogExists(String jobCode) throws Exception {
        try (Connection connection = dataSource.getConnection(); PreparedStatement statement = connection.prepareStatement(
                "SELECT COUNT(*) FROM sys_job_log WHERE job_code = ?")) {
            statement.setString(1, jobCode);
            try (var result = statement.executeQuery()) {
                result.next();
                org.junit.jupiter.api.Assertions.assertTrue(result.getInt(1) >= 1);
            }
        }
    }

    private void insertRole(Connection c, String id, String code) throws Exception {
        try (PreparedStatement s = c.prepareStatement("INSERT INTO sys_role (id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'OWNER')")) {
            s.setString(1, id); s.setString(2, code); s.setString(3, code); s.executeUpdate();
        }
    }

    private void insertUser(Connection c, String id, String username) throws Exception {
        try (PreparedStatement s = c.prepareStatement("INSERT INTO sys_user (id, username, password_hash, display_name, enabled, must_change_password, failed_login_count, credential_version, permission_version, mfa_required) VALUES (UUID_TO_BIN(?, 0), ?, ?, ?, TRUE, FALSE, 0, 1, 1, FALSE)")) {
            s.setString(1, id); s.setString(2, username); s.setString(3, PASSWORD_HASH); s.setString(4, username); s.executeUpdate();
        }
    }

    private void insertRolePermissions(Connection c, String roleId) throws Exception {
        try (PreparedStatement s = c.prepareStatement("INSERT INTO sys_role_permission (role_id, permission_id) SELECT UUID_TO_BIN(?, 0), id FROM sys_permission")) {
            s.setString(1, roleId); s.executeUpdate();
        }
    }

    private void insertUserRole(Connection c, String userId, String roleId) throws Exception {
        try (PreparedStatement s = c.prepareStatement("INSERT INTO sys_user_role (user_id, role_id) VALUES (UUID_TO_BIN(?, 0), UUID_TO_BIN(?, 0))")) {
            s.setString(1, userId); s.setString(2, roleId); s.executeUpdate();
        }
    }

    private void deleteOwnedRecords(Connection c, String userId) throws Exception {
        try (PreparedStatement s = c.prepareStatement("DELETE FROM sys_notice WHERE owner_id = UUID_TO_BIN(?, 0)")) {
            s.setString(1, userId); s.executeUpdate();
        }
        try (PreparedStatement s = c.prepareStatement("DELETE FROM sys_job WHERE created_by = UUID_TO_BIN(?, 0)")) {
            s.setString(1, userId); s.executeUpdate();
        }
    }

    private void deleteUser(Connection c, String id) throws Exception {
        try (PreparedStatement s = c.prepareStatement("DELETE FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) { s.setString(1, id); s.executeUpdate(); }
    }

    private void deleteRole(Connection c, String id) throws Exception {
        try (PreparedStatement s = c.prepareStatement("DELETE FROM sys_role WHERE id = UUID_TO_BIN(?, 0)")) { s.setString(1, id); s.executeUpdate(); }
    }

    private void clearLoginRateLimits(Connection c) throws Exception {
        try (PreparedStatement s = c.prepareStatement("DELETE FROM sys_login_rate_limit")) { s.executeUpdate(); }
    }
}
