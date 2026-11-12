package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.sql.DataSource;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * 保存和更新用户 TOTP 状态。
 *
 * <p>本类只处理密文、验证码时间步和锁定状态。明文 TOTP 密钥由调用方先经
 * {@link MfaSecretCipher} 加密后传入，仓储不会解密或返回明文。</p>
 */
@ApplicationScoped
public class MfaRepository {
    public static final int MAX_FAILURES = 5;
    public static final int LOCK_SECONDS = 300;

    @Inject DataSource dataSource;

    /** 读取用户是否要求 MFA 以及当前是否存在已启用的 TOTP。 */
    public Optional<MfaStatus> findStatus(long userId) {
        requireUser(userId);
        String sql = "SELECT u.mfa_required, m.id, COALESCE(m.enabled, 0) AS enabled "
                + "FROM sys_user u LEFT JOIN sys_user_mfa m ON m.user_id = u.id WHERE u.id = ?";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setLong(1, userId);
            try (var rs = p.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(new MfaStatus(userId, rs.getBoolean("mfa_required"),
                        rs.getString("id"), rs.getBoolean("enabled")));
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not read MFA status", e);
        }
    }

    /**
     * 创建或替换尚未启用的 enrollment。先锁定用户行，再检查 MFA 记录，避免同一用户
     * 并发创建两条记录；已启用的记录必须经过单独的撤销流程，不能被覆盖。
     */
    public boolean replacePendingEnrollment(long userId, String mfaId, MfaSecretCipher.EncryptedSecret encrypted) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        requireEncrypted(encrypted);
        try (var c = dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                if (!userExistsForUpdate(c, userId)) {
                    c.rollback();
                    return false;
                }
                Long owner = mfaOwnerForUpdate(c, boundMfaId);
                if (owner != null && owner != userId) {
                    c.rollback();
                    return false;
                }
                MfaRow existing = userMfaForUpdate(c, userId);
                if (existing != null && existing.enabled()) {
                    c.rollback();
                    return false;
                }
                if (existing == null) {
                    insertPending(c, userId, boundMfaId, encrypted);
                } else {
                    updatePending(c, userId, existing.id(), boundMfaId, encrypted);
                }
                c.commit();
                return true;
            } catch (Exception e) {
                c.rollback();
                throw e;
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not save MFA enrollment", e);
        }
    }

    /** 读取指定用户的 TOTP 密文和验证状态；返回值不包含任何明文秘密。 */
    public Optional<StoredMfa> find(long userId, String mfaId) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        String sql = "SELECT id, user_id, secret_ciphertext, secret_nonce, key_version, enabled, "
                + "last_accepted_step, locked_until FROM sys_user_mfa WHERE user_id = ? AND id = ?";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setLong(1, userId);
            p.setString(2, boundMfaId);
            try (var rs = p.executeQuery()) {
                return rs.next() ? Optional.of(readStored(rs)) : Optional.empty();
            }
        } catch (Exception e) {
            throw new IllegalStateException("Could not read MFA enrollment", e);
        }
    }

    /**
     * 原子接受一个 TOTP 时间步。登录只允许已启用记录；enrollment 校验可以显式允许待启用记录。
     * 条件更新同时阻止锁定期间验证和同一时间步的并发重复使用。
     */
    public boolean acceptTotp(long userId, String mfaId, long candidateStep, boolean enrollmentVerification) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        if (candidateStep < 0) throw new IllegalArgumentException("candidateStep must be non-negative");
        String sql = "UPDATE sys_user_mfa SET last_accepted_step = ?, last_used_at = CURRENT_TIMESTAMP, "
                + "failed_attempt_count = 0, locked_until = NULL WHERE user_id = ? AND id = ? "
                + "AND (enabled = 1 OR (? = 1 AND enabled = 0)) "
                + "AND (locked_until IS NULL OR locked_until <= CURRENT_TIMESTAMP) "
                + "AND (last_accepted_step IS NULL OR last_accepted_step < ?)";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setLong(1, candidateStep);
            p.setLong(2, userId);
            p.setString(3, boundMfaId);
            p.setInt(4, enrollmentVerification ? 1 : 0);
            p.setLong(5, candidateStep);
            return p.executeUpdate() == 1;
        } catch (Exception e) {
            throw new IllegalStateException("Could not accept MFA code", e);
        }
    }

    /** 记录一次失败验证；达到阈值时在数据库内设置短时锁定。 */
    public boolean recordFailure(long userId, String mfaId) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        String sql = "UPDATE sys_user_mfa SET failed_attempt_count = failed_attempt_count + 1, "
                + "locked_until = CASE WHEN failed_attempt_count + 1 >= ? "
                + "THEN TIMESTAMPADD(SECOND, ?, CURRENT_TIMESTAMP) ELSE locked_until END "
                + "WHERE user_id = ? AND id = ? AND (locked_until IS NULL OR locked_until <= CURRENT_TIMESTAMP)";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setInt(1, MAX_FAILURES);
            p.setInt(2, LOCK_SECONDS);
            p.setLong(3, userId);
            p.setString(4, boundMfaId);
            return p.executeUpdate() == 1;
        } catch (Exception e) {
            throw new IllegalStateException("Could not record MFA failure", e);
        }
    }

    /** 只有已经成功接受一个 enrollment 时间步的待启用记录才可以转为已启用。 */
    public boolean enableEnrollment(long userId, String mfaId) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        String sql = "UPDATE sys_user_mfa SET enabled = 1, enrolled_at = CURRENT_TIMESTAMP, "
                + "failed_attempt_count = 0, locked_until = NULL WHERE user_id = ? AND id = ? "
                + "AND enabled = 0 AND last_accepted_step IS NOT NULL";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            p.setLong(1, userId);
            p.setString(2, boundMfaId);
            return p.executeUpdate() == 1;
        } catch (Exception e) {
            throw new IllegalStateException("Could not enable MFA enrollment", e);
        }
    }

    private static void requireUser(long userId) {
        if (userId <= 0) throw new IllegalArgumentException("userId must be positive");
    }

    private static String normalizeMfaId(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("mfaId is required");
        try {
            return UUID.fromString(value.trim()).toString();
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("mfaId must be a UUID", e);
        }
    }

    private static void requireEncrypted(MfaSecretCipher.EncryptedSecret encrypted) {
        if (encrypted == null) throw new IllegalArgumentException("encrypted MFA secret is required");
    }

    private static boolean userExistsForUpdate(java.sql.Connection c, long userId) throws Exception {
        try (var p = c.prepareStatement("SELECT id FROM sys_user WHERE id = ? FOR UPDATE")) {
            p.setLong(1, userId);
            try (var rs = p.executeQuery()) { return rs.next(); }
        }
    }

    private static Long mfaOwnerForUpdate(java.sql.Connection c, String mfaId) throws Exception {
        try (var p = c.prepareStatement("SELECT user_id FROM sys_user_mfa WHERE id = ? FOR UPDATE")) {
            p.setString(1, mfaId);
            try (var rs = p.executeQuery()) { return rs.next() ? rs.getLong(1) : null; }
        }
    }

    private static MfaRow userMfaForUpdate(java.sql.Connection c, long userId) throws Exception {
        try (var p = c.prepareStatement("SELECT id, enabled FROM sys_user_mfa WHERE user_id = ? FOR UPDATE")) {
            p.setLong(1, userId);
            try (var rs = p.executeQuery()) { return rs.next() ? new MfaRow(rs.getString("id"), rs.getBoolean("enabled")) : null; }
        }
    }

    private static void insertPending(java.sql.Connection c, long userId, String mfaId,
                                      MfaSecretCipher.EncryptedSecret encrypted) throws Exception {
        try (var p = c.prepareStatement("INSERT INTO sys_user_mfa(id, user_id, mfa_type, secret_ciphertext, secret_nonce, key_version, enabled, failed_attempt_count) VALUES (?, ?, 'TOTP', ?, ?, ?, 0, 0)")) {
            p.setString(1, mfaId);
            p.setLong(2, userId);
            p.setBytes(3, encrypted.ciphertext());
            p.setBytes(4, encrypted.nonce());
            p.setInt(5, encrypted.keyVersion());
            p.executeUpdate();
        }
    }

    private static void updatePending(java.sql.Connection c, long userId, String oldMfaId, String newMfaId,
                                      MfaSecretCipher.EncryptedSecret encrypted) throws Exception {
        try (var p = c.prepareStatement("UPDATE sys_user_mfa SET id = ?, secret_ciphertext = ?, secret_nonce = ?, key_version = ?, enabled = 0, enrolled_at = NULL, last_used_at = NULL, failed_attempt_count = 0, locked_until = NULL, last_accepted_step = NULL WHERE user_id = ? AND id = ? AND enabled = 0")) {
            p.setString(1, newMfaId);
            p.setBytes(2, encrypted.ciphertext());
            p.setBytes(3, encrypted.nonce());
            p.setInt(4, encrypted.keyVersion());
            p.setLong(5, userId);
            p.setString(6, oldMfaId);
            if (p.executeUpdate() != 1) throw new IllegalStateException("MFA enrollment changed concurrently");
        }
    }

    private static StoredMfa readStored(java.sql.ResultSet rs) throws Exception {
        long step = rs.getLong("last_accepted_step");
        Long acceptedStep = rs.wasNull() ? null : step;
        Timestamp locked = rs.getTimestamp("locked_until");
        var encrypted = new MfaSecretCipher.EncryptedSecret(rs.getBytes("secret_nonce"),
                rs.getBytes("secret_ciphertext"), rs.getInt("key_version"));
        return new StoredMfa(rs.getString("id"), rs.getLong("user_id"), encrypted,
                rs.getBoolean("enabled"), acceptedStep, locked == null ? null : locked.toInstant());
    }

    private record MfaRow(String id, boolean enabled) {}

    public record MfaStatus(long userId, boolean required, String mfaId, boolean enabled) {}

    /** 数据库中的 MFA 记录只携带密文和状态字段，调用方需要自行通过密钥服务解密。 */
    public record StoredMfa(String id, long userId, MfaSecretCipher.EncryptedSecret encrypted,
                            boolean enabled, Long lastAcceptedStep, Instant lockedUntil) {}
}
