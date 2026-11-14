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
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

/** 通过真实 MySQL HTTP 链路验证公告和任务的 OWNER 数据范围。 */
@QuarkusTest
class OwnerScopeResourceHttpTest {
    private static final String PASSWORD_HASH = "$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W";

    @Inject DataSource dataSource;
    private String ownerRole, otherRole, ownerId, otherId, ownerName, otherName;
    private String ownerToken, otherToken, noticeId, jobId, otherNoticeId, otherJobId;

    @BeforeEach
    void createSelfScopedSubjects() throws Exception {
        ownerRole = UuidValues.v7();
        otherRole = UuidValues.v7();
        ownerId = UuidValues.v7();
        otherId = UuidValues.v7();
        ownerName = "owner_scope_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        otherName = "other_scope_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        try (Connection connection = dataSource.getConnection()) {
            clearLoginRateLimits(connection);
            insertRole(connection, ownerRole, "owner_role");
            insertRole(connection, otherRole, "other_role");
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
    void removeSubjects() throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            deleteUser(connection, ownerId);
            deleteUser(connection, otherId);
            deleteRole(connection, ownerRole);
            deleteRole(connection, otherRole);
        }
    }

    @Test
    void ownerCanManageRecordsAndOtherSelfSubjectCannotSeeThem() {
        noticeId = createNotice(ownerToken, "所有者公告");
        jobId = createJob(ownerToken);
        otherNoticeId = createNotice(otherToken, "另一主体公告");
        otherJobId = createJob(otherToken);

        given().auth().oauth2(ownerToken).when().get("/v1/notices/manage")
                .then().statusCode(200).body("data", hasSize(1));
        given().auth().oauth2(ownerToken).when().get("/v1/jobs")
                .then().statusCode(200).body("data", hasSize(1));
        given().auth().oauth2(otherToken).when().get("/v1/notices/manage")
                .then().statusCode(200).body("data", hasSize(1));
        given().auth().oauth2(otherToken).when().get("/v1/jobs")
                .then().statusCode(200).body("data", hasSize(1));

        given().auth().oauth2(otherToken).contentType(JSON)
                .body("{\"title\":\"越界修改\",\"content\":\"deny\"}")
                .when().put("/v1/notices/" + noticeId).then().statusCode(404);
        given().auth().oauth2(otherToken).when().post("/v1/jobs/" + jobId + "/run")
                .then().statusCode(404);
        given().auth().oauth2(otherToken).when().get("/v1/jobs/logs?jobId=" + jobId)
                .then().statusCode(403);

        given().auth().oauth2(otherToken).contentType(JSON)
                .body("{\"title\":\"另一主体更新\",\"content\":\"updated\"}")
                .when().put("/v1/notices/" + otherNoticeId).then().statusCode(200);
        given().auth().oauth2(otherToken).when().post("/v1/jobs/" + otherJobId + "/run")
                .then().statusCode(200);
        given().auth().oauth2(otherToken).when().delete("/v1/notices/" + otherNoticeId)
                .then().statusCode(200);
        given().auth().oauth2(otherToken).when().delete("/v1/jobs/" + otherJobId)
                .then().statusCode(200);

        given().auth().oauth2(ownerToken).contentType(JSON)
                .body("{\"title\":\"所有者更新\",\"content\":\"updated\"}")
                .when().put("/v1/notices/" + noticeId).then().statusCode(200);
        given().auth().oauth2(ownerToken).when().post("/v1/jobs/" + jobId + "/run")
                .then().statusCode(200).body("data.triggered", is(true));
        given().auth().oauth2(ownerToken).when().get("/v1/jobs/logs?jobId=" + jobId)
                .then().statusCode(200).body("data.total", greaterThanOrEqualTo(1));
        given().auth().oauth2(ownerToken).when().delete("/v1/notices/" + noticeId)
                .then().statusCode(200);
        given().auth().oauth2(ownerToken).when().delete("/v1/jobs/" + jobId)
                .then().statusCode(200);
    }

    private String createNotice(String token, String title) {
        return given().auth().oauth2(token).contentType(JSON)
                .body("{\"title\":\"" + title + "\",\"content\":\"owner content\",\"noticeType\":\"NOTICE\"}")
                .when().post("/v1/notices").then().statusCode(201).extract().path("data.id");
    }

    private String createJob(String token) {
        String body = "{\"code\":\"owner-job-" + UUID.randomUUID().toString().replace("-", "").substring(0, 16)
                + "\",\"name\":\"所有者任务\",\"cron\":\"0/30 * * * * ?\","
                + "\"invokeTarget\":\"keystoneJob.heartbeat()\",\"concurrent\":false,\"enabled\":false}";
        return given().auth().oauth2(token).contentType(JSON).body(body)
                .when().post("/v1/jobs").then().statusCode(201).extract().path("data.id");
    }

    private String login(String username) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private void insertRole(Connection c, String id, String code) throws Exception {
        try (PreparedStatement s = c.prepareStatement("INSERT INTO sys_role (id, code, name, enabled, data_scope) VALUES (UUID_TO_BIN(?, 0), ?, ?, TRUE, 'OWNER')")) {
            s.setString(1, id); s.setString(2, code + "_" + id.substring(0, 8)); s.setString(3, code); s.executeUpdate();
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
