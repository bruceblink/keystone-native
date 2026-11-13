package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证 MFA 认证请求、TOTP 状态和恢复码使用 ORM 事务。 */
class MfaOrmPersistenceTest {
    @Test
    void mfaRepositoriesUseOrmWithoutManualJdbc() throws Exception {
        String mfa = Files.readString(Path.of("src/main/java/app/keystone/auth/MfaRepository.java"));
        String challenge = Files.readString(Path.of("src/main/java/app/keystone/auth/MfaChallengeRepository.java"));
        assertTrue(mfa.contains("UserMfaOrmRepository"));
        assertTrue(mfa.contains("MfaRecoveryCodeOrmRepository"));
        assertTrue(mfa.contains("@Transactional"));
        assertTrue(challenge.contains("AuthChallengeOrmRepository"));
        assertTrue(challenge.contains("@Transactional"));
        assertFalse(mfa.contains("DataSource"));
        assertFalse(mfa.contains("prepareStatement"));
        assertFalse(challenge.contains("DataSource"));
        assertFalse(challenge.contains("prepareStatement"));
    }

    @Test
    void mfaEntitiesPreserveEncryptedAndOneTimeFields() throws Exception {
        String mfa = Files.readString(Path.of("src/main/java/app/keystone/auth/UserMfaEntity.java"));
        String recovery = Files.readString(Path.of("src/main/java/app/keystone/auth/MfaRecoveryCodeEntity.java"));
        String challenge = Files.readString(Path.of("src/main/java/app/keystone/auth/AuthChallengeEntity.java"));
        assertTrue(mfa.contains("secret_ciphertext"));
        assertTrue(mfa.contains("secret_nonce"));
        assertTrue(mfa.contains("last_accepted_step"));
        assertTrue(recovery.contains("code_hash"));
        assertTrue(recovery.contains("used_at"));
        assertTrue(challenge.contains("consumed_at"));
        assertTrue(challenge.contains("attempt_count"));
    }
}
