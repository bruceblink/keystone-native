package app.keystone;

import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;

import javax.sql.DataSource;

/** Resets shared authentication state before each integration test. */
abstract class AuthTestFixture {
    @Inject DataSource dataSource;

    @BeforeEach
    void resetAuthenticationFixture() throws Exception {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_user SET password_hash = '$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W', must_change_password = false WHERE username = 'admin'")) { p.executeUpdate(); }
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_refresh_token SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = (SELECT id FROM sys_user WHERE username = 'admin') AND revoked_at IS NULL")) { p.executeUpdate(); }
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("UPDATE sys_auth_session SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = (SELECT id FROM sys_user WHERE username = 'admin') AND revoked_at IS NULL")) { p.executeUpdate(); }
        try (var c = dataSource.getConnection(); var p = c.prepareStatement("DELETE FROM sys_login_rate_limit")) { p.executeUpdate(); }
    }
}
