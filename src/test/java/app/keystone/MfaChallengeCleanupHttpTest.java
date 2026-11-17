package app.keystone;

import app.keystone.auth.MfaChallengeRepository;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.sql.Timestamp;
import java.time.Instant;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 通过真实 MySQL 验证过期认证请求分批删除并保留有效请求。 */
@QuarkusTest
class MfaChallengeCleanupHttpTest extends AuthTestFixture {
    @Inject MfaChallengeRepository challenges;

    @Test
    void cleanupDeletesOnlyTheRequestedBatchOfExpiredChallenges() throws Exception {
        String firstSessionId = loginAdminSession();
        String userId = adminUserId();
        String secondSessionId = loginAdminSession();
        Instant now = Instant.now();
        var firstExpired = challenges.create(userId, MfaChallengeRepository.Purpose.STEP_UP,
                "web", firstSessionId, null, now.plusSeconds(300));
        var secondExpired = challenges.create(userId, MfaChallengeRepository.Purpose.STEP_UP,
                "web", firstSessionId, null, now.plusSeconds(300));
        var expiredWithinIssueWindow = challenges.create(userId, MfaChallengeRepository.Purpose.STEP_UP,
                "web", secondSessionId, null, now.plusSeconds(300));
        var active = challenges.create(userId, MfaChallengeRepository.Purpose.STEP_UP,
                "web", firstSessionId, null, now.plusSeconds(300));
        setOldExpired(firstExpired.id(), Instant.parse("2001-01-01T00:00:00Z"));
        setOldExpired(secondExpired.id(), Instant.parse("2001-01-02T00:00:00Z"));
        setExpiry(expiredWithinIssueWindow.id(), Instant.parse("2001-01-03T00:00:00Z"));

        Instant issueWindowCutoff = now.minusSeconds(3600);
        assertEquals(1, challenges.deleteExpiredBatch(now, issueWindowCutoff, 1));
        assertFalse(challengeExists(firstExpired.id()));
        assertTrue(challengeExists(secondExpired.id()));
        assertTrue(challengeExists(expiredWithinIssueWindow.id()));
        assertTrue(challengeExists(active.id()));
        assertTrue(challenges.createStepUp(userId, "web", secondSessionId, null,
                issueWindowCutoff, 1, now.plusSeconds(300)).isEmpty());

        assertEquals(1, challenges.deleteExpiredBatch(now, issueWindowCutoff, 1));
        assertFalse(challengeExists(secondExpired.id()));
        assertTrue(challengeExists(expiredWithinIssueWindow.id()));
        assertTrue(challengeExists(active.id()));

        Instant afterIssueWindow = now.plusSeconds(3601);
        assertTrue(challenges.deleteExpiredBatch(afterIssueWindow,
                afterIssueWindow.minusSeconds(3600), 500) >= 2);
        assertFalse(challengeExists(expiredWithinIssueWindow.id()));
        assertFalse(challengeExists(active.id()));
    }

    private String adminUserId() throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("SELECT BIN_TO_UUID(id, 0) FROM sys_user WHERE username = ?")) {
            statement.setString(1, "admin");
            try (var result = statement.executeQuery()) {
                if (!result.next()) throw new IllegalStateException("test administrator is missing");
                return result.getString(1);
            }
        }
    }

    private String loginAdminSession() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.sessionId");
    }

    private void setExpiry(String challengeId, Instant expiresAt) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("UPDATE sys_auth_challenge SET expires_at = ? WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setTimestamp(1, Timestamp.from(expiresAt));
            statement.setString(2, challengeId);
            assertEquals(1, statement.executeUpdate());
        }
    }

    private void setOldExpired(String challengeId, Instant expiresAt) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("UPDATE sys_auth_challenge SET expires_at = ?, created_at = ? WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setTimestamp(1, Timestamp.from(expiresAt));
            statement.setTimestamp(2, Timestamp.from(expiresAt));
            statement.setString(3, challengeId);
            assertEquals(1, statement.executeUpdate());
        }
    }

    private boolean challengeExists(String challengeId) throws Exception {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("SELECT COUNT(*) FROM sys_auth_challenge WHERE id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, challengeId);
            try (var result = statement.executeQuery()) {
                return result.next() && result.getInt(1) == 1;
            }
        }
    }
}
