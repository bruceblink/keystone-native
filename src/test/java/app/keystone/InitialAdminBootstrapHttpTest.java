package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import jakarta.inject.Inject;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Instant;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.quarkus.elytron.security.common.BcryptUtil;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 使用真实 MySQL 和 HTTP 验证初始管理员迁移与首次改密流程。 */
@QuarkusTest
class InitialAdminBootstrapHttpTest {
    private static final String ADMIN_ID = "5faed4bb-63af-5158-bd3c-1200c539cfd9";
    private static final Pattern V46_SEED_HASH = Pattern.compile("'admin',\\s*'([^']+)'", Pattern.DOTALL);
    private static final Pattern V12_PASSWORD_HASH = Pattern.compile("SET password_hash = '([^']+)'", Pattern.DOTALL);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Inject DataSource dataSource;

    private AdminState savedAdmin;
    private long savedAdminSessionCount;
    private String bootstrapUserId;
    private String bootstrapUsername;

    @BeforeEach
    void saveSeedState() throws Exception {
        savedAdmin = readAdminState();
        savedAdminSessionCount = adminSessionCount();
    }

    @AfterEach
    void restoreSeedState() throws Exception {
        if (savedAdmin == null) return;

        try (Connection connection = dataSource.getConnection()) {
            // 只删除本测试创建的账号；管理员原有会话必须保留。
            if (bootstrapUserId != null) {
                try (PreparedStatement statement = connection.prepareStatement(
                        "DELETE FROM sys_user WHERE id = UUID_TO_BIN(?, 0)")) {
                    statement.setString(1, bootstrapUserId);
                    statement.executeUpdate();
                }
            }

            try (PreparedStatement statement = connection.prepareStatement("""
                    UPDATE sys_user
                    SET password_hash = ?, enabled = ?, login_ip = ?, login_at = ?,
                        must_change_password = ?, failed_login_count = ?, locked_until = ?,
                        credential_version = ?, last_password_changed_at = ?
                    WHERE id = UUID_TO_BIN(?, 0)
                    """)) {
                statement.setString(1, savedAdmin.passwordHash());
                statement.setBoolean(2, savedAdmin.enabled());
                statement.setString(3, savedAdmin.loginIp());
                statement.setTimestamp(4, savedAdmin.loginAt());
                statement.setBoolean(5, savedAdmin.mustChangePassword());
                statement.setInt(6, savedAdmin.failedLoginCount());
                statement.setTimestamp(7, savedAdmin.lockedUntil());
                statement.setLong(8, savedAdmin.credentialVersion());
                statement.setTimestamp(9, savedAdmin.lastPasswordChangedAt());
                statement.setString(10, ADMIN_ID);
                statement.executeUpdate();
            }
        }

        assertEquals(savedAdminSessionCount, adminSessionCount(),
                "the test must preserve all pre-existing administrator sessions");
    }

    @Test
    void flywaySeedRequiresPasswordChangeAndSupportsTheHttpBootstrapFlow() throws Exception {
        applyOriginalSeedMigration();
        assertFlywayAppliedV59();
        AdminState state = readAdminStateUnchecked();
        assertTrue(state.enabled(), "the seeded administrator must stay enabled");
        assertTrue(state.mustChangePassword(), "the seed must require an initial password change");
        assertTrue(BcryptUtil.matches("password", state.passwordHash()),
                "the documented initial password must match the migrated seed");

        given().contentType(JSON)
                .body(Map.of("username", "admin", "password", "password"))
                .when().post("/v1/auth/login")
                .then().statusCode(428)
                .body("error.code", is("precondition_required"));

        String replacement = replacementPassword();
        String passwordHash = migrationHash("V12__use_supported_bcrypt_prefix.sql", V12_PASSWORD_HASH);
        createBootstrapTestUser(passwordHash);

        given().contentType(JSON)
                .body(Map.of(
                        "username", bootstrapUsername,
                        "currentPassword", "password",
                        "newPassword", replacement))
                .when().post("/v1/auth/change-initial-password")
                .then().statusCode(200)
                .body("data.updated", is(true));

        given().contentType(JSON)
                .body(Map.of("username", bootstrapUsername, "password", replacement))
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .body("success", is(true));
    }

    @Test
    void v59RepairsOnlyTheExactUnusedSeedAndIsIdempotent() throws Exception {
        String oldHash = migrationHash("V46__uuid_identity_core.sql", V46_SEED_HASH);
        String migration = executableMigration("V59__repair_initial_admin.sql");

        inRollback(connection -> {
            setAdminState(connection, oldHash, true, null, null, false, 1);
            assertEquals(1, applyMigration(connection, migration),
                    "the untouched V46 seed must be repaired once");
            assertRepairedSeed(connection);
            assertEquals(0, applyMigration(connection, migration),
                    "replaying V59 must not change the repaired seed");
        });

        inRollback(connection -> {
            Timestamp priorLogin = Timestamp.from(Instant.now().truncatedTo(ChronoUnit.SECONDS));
            setAdminState(connection, oldHash, true, null, priorLogin, false, 1);
            assertEquals(0, applyMigration(connection, migration),
                    "an administrator with a successful login must not be changed");
            assertOriginalState(connection, oldHash, true, priorLogin, false, 1);
        });

        inRollback(connection -> {
            setAdminState(connection, oldHash, false, null, null, false, 1);
            assertEquals(0, applyMigration(connection, migration),
                    "a disabled administrator must not be reactivated or rewritten");
            assertOriginalState(connection, oldHash, false, null, false, 1);
        });

        inRollback(connection -> {
            String caseVariant = changeHashCase(oldHash);
            setAdminState(connection, caseVariant, true, null, null, false, 1);
            assertEquals(0, applyMigration(connection, migration),
                    "a case-different hash must not match the seed fingerprint");
            assertOriginalState(connection, caseVariant, true, null, false, 1);
        });

        inRollback(connection -> {
            setAdminState(connection, BcryptUtil.bcryptHash(replacementPassword()), true,
                    Timestamp.from(Instant.now()), null, false, 1);
            String changedHash = passwordHash(connection);
            assertEquals(0, applyMigration(connection, migration),
                    "an administrator with a changed password must not be rewritten");
            assertTrue(changedHash.equals(passwordHash(connection)),
                    "the changed password hash must remain unchanged");
            assertTrue(lastPasswordChangedAt(connection) != null,
                    "the password-change timestamp must remain unchanged");
        });
    }

    private AdminState readAdminState() throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     SELECT password_hash, enabled, login_ip, login_at, must_change_password,
                            failed_login_count, locked_until, credential_version, last_password_changed_at
                     FROM sys_user WHERE id = UUID_TO_BIN(?, 0)
                     """)) {
            statement.setString(1, ADMIN_ID);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next(), "Flyway must seed the default administrator");
                return new AdminState(
                        result.getString("password_hash"),
                        result.getBoolean("enabled"),
                        result.getString("login_ip"),
                        result.getTimestamp("login_at"),
                        result.getBoolean("must_change_password"),
                        result.getInt("failed_login_count"),
                        result.getTimestamp("locked_until"),
                        result.getLong("credential_version"),
                        result.getTimestamp("last_password_changed_at"));
            }
        }
    }

    private long adminSessionCount() throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM sys_auth_session WHERE user_id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, ADMIN_ID);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next());
                return result.getLong(1);
            }
        }
    }

    private AdminState readAdminStateUnchecked() {
        try {
            return readAdminState();
        } catch (SQLException error) {
            throw new IllegalStateException("Could not read seeded administrator state", error);
        }
    }

    private static String migrationHash(String fileName, Pattern pattern) throws Exception {
        Matcher matcher = pattern.matcher(Files.readString(Path.of("src/main/resources/db/migration", fileName)));
        assertTrue(matcher.find(), "migration must contain the expected seed hash");
        return matcher.group(1);
    }

    private static String executableMigration(String fileName) throws Exception {
        return Files.readString(Path.of("src/main/resources/db/migration", fileName))
                .replaceAll("(?m)^\\s*--.*$", "")
                .trim();
    }

    // 每个 SQL 场景使用真实 MySQL 事务，完成断言后回滚测试数据。
    private void inRollback(SqlScenario scenario) throws Exception {
        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                scenario.run(connection);
            } finally {
                connection.rollback();
            }
        }
    }

    // 在独立测试数据库重放已登记的 V59 SQL，模拟 V58 中未使用的原始管理员行。
    private void applyOriginalSeedMigration() throws Exception {
        String oldHash = migrationHash("V46__uuid_identity_core.sql", V46_SEED_HASH);
        String migration = executableMigration("V59__repair_initial_admin.sql");

        try (Connection connection = dataSource.getConnection()) {
            connection.setAutoCommit(false);
            try {
                setAdminState(connection, oldHash, true, null, null, false, 1);
                assertEquals(1, applyMigration(connection, migration),
                        "the original administrator fingerprint must be repaired");
                assertRepairedSeed(connection);
                connection.commit();
            } catch (Exception error) {
                connection.rollback();
                throw error;
            }
        }
    }

    private void createBootstrapTestUser(String passwordHash) throws SQLException {
        bootstrapUserId = UUID.randomUUID().toString();
        bootstrapUsername = "v59_bootstrap_" + UUID.randomUUID().toString().replace("-", "");

        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement("""
                     INSERT INTO sys_user
                         (id, username, password_hash, display_name, enabled, must_change_password,
                          credential_version, permission_version)
                     VALUES (UUID_TO_BIN(?, 0), ?, ?, 'Migration test account', TRUE, TRUE, 1, 1)
                     """)) {
            statement.setString(1, bootstrapUserId);
            statement.setString(2, bootstrapUsername);
            statement.setString(3, passwordHash);
            statement.executeUpdate();
        }
    }

    private void assertFlywayAppliedV59() throws SQLException {
        try (Connection connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM flyway_schema_history WHERE version = '59' AND success = TRUE");
             ResultSet result = statement.executeQuery()) {
            assertTrue(result.next());
            assertEquals(1, result.getInt(1), "Flyway must apply V59 to the isolated MySQL database");
        }
    }

    private static int applyMigration(Connection connection, String migration) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            return statement.executeUpdate(migration);
        }
    }

    private static void setAdminState(Connection connection, String hash, boolean enabled,
                                      Timestamp lastPasswordChangedAt, Timestamp loginAt,
                                      boolean mustChangePassword, long credentialVersion) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                UPDATE sys_user
                SET password_hash = ?, enabled = ?, last_password_changed_at = ?, login_at = ?,
                    must_change_password = ?, credential_version = ?, failed_login_count = 0,
                    locked_until = NULL
                WHERE id = UUID_TO_BIN(?, 0)
                """)) {
            statement.setString(1, hash);
            statement.setBoolean(2, enabled);
            statement.setTimestamp(3, lastPasswordChangedAt);
            statement.setTimestamp(4, loginAt);
            statement.setBoolean(5, mustChangePassword);
            statement.setLong(6, credentialVersion);
            statement.setString(7, ADMIN_ID);
            statement.executeUpdate();
        }
    }

    private static void assertRepairedSeed(Connection connection) throws SQLException {
        AdminState state = readAdminState(connection);
        assertTrue(BcryptUtil.matches("password", state.passwordHash()),
                "V59 must install the documented initial password");
        assertTrue(state.mustChangePassword(), "V59 must force an initial password change");
    }

    private static void assertOriginalState(Connection connection, String expectedHash, boolean enabled,
                                            Timestamp expectedLoginAt, boolean mustChangePassword,
                                            long credentialVersion) throws SQLException {
        AdminState state = readAdminState(connection);
        assertTrue(expectedHash.equals(state.passwordHash()), "V59 must preserve the existing password hash");
        assertEquals(enabled, state.enabled());
        assertEquals(expectedLoginAt, state.loginAt());
        assertEquals(mustChangePassword, state.mustChangePassword());
        assertEquals(credentialVersion, state.credentialVersion());
    }

    private static AdminState readAdminState(Connection connection) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement("""
                SELECT password_hash, enabled, login_ip, login_at, must_change_password,
                       failed_login_count, locked_until, credential_version, last_password_changed_at
                FROM sys_user WHERE id = UUID_TO_BIN(?, 0)
                """)) {
            statement.setString(1, ADMIN_ID);
            try (ResultSet result = statement.executeQuery()) {
                assertTrue(result.next(), "administrator row must remain present");
                return new AdminState(result.getString("password_hash"), result.getBoolean("enabled"),
                        result.getString("login_ip"), result.getTimestamp("login_at"),
                        result.getBoolean("must_change_password"), result.getInt("failed_login_count"),
                        result.getTimestamp("locked_until"), result.getLong("credential_version"),
                        result.getTimestamp("last_password_changed_at"));
            }
        }
    }

    private static String passwordHash(Connection connection) throws SQLException {
        return readAdminState(connection).passwordHash();
    }

    private static Timestamp lastPasswordChangedAt(Connection connection) throws SQLException {
        return readAdminState(connection).lastPasswordChangedAt();
    }

    private static String changeHashCase(String value) {
        for (int index = 7; index < value.length(); index++) {
            char character = value.charAt(index);
            if (Character.isLowerCase(character)) {
                return value.substring(0, index) + Character.toUpperCase(character) + value.substring(index + 1);
            }
            if (Character.isUpperCase(character)) {
                return value.substring(0, index) + Character.toLowerCase(character) + value.substring(index + 1);
            }
        }
        throw new IllegalStateException("Seed hash must contain a case-sensitive character");
    }

    private static String replacementPassword() {
        return "Nw-" + Long.toUnsignedString(RANDOM.nextLong(), 36) + "-a1!";
    }

    private record AdminState(String passwordHash, boolean enabled, String loginIp, Timestamp loginAt,
                              boolean mustChangePassword, int failedLoginCount, Timestamp lockedUntil,
                              long credentialVersion, Timestamp lastPasswordChangedAt) {}

    @FunctionalInterface
    private interface SqlScenario {
        void run(Connection connection) throws Exception;
    }
}
