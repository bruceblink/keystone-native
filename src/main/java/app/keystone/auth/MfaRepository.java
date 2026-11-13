package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/** 保存和更新用户 TOTP 状态、认证请求和一次性恢复码。 */
@ApplicationScoped
public class MfaRepository {
    public static final int MAX_FAILURES = 5;
    public static final int LOCK_SECONDS = 300;

    @Inject ApiKeyUserRepository users;
    @Inject MfaChallengeRepository challenges;
    @Inject UserMfaOrmRepository mfaRecords;
    @Inject MfaRecoveryCodeOrmRepository recoveryCodes;

    /** 读取用户 MFA 策略和当前已保存的 TOTP 状态。 */
    @Transactional
    public Optional<MfaStatus> findStatus(long userId) {
        requireUser(userId);
        ApiKeyUserEntity user = users.findById(userId);
        if (user == null) return Optional.empty();
        UserMfaEntity mfa = mfaRecords.findByUser(userId);
        return Optional.of(new MfaStatus(userId, user.mfaRequired(), mfa == null ? null : mfa.id(),
                mfa != null && mfa.enabled()));
    }

    /** 创建或替换尚未启用的 enrollment，先锁定用户行。 */
    @Transactional
    public boolean replacePendingEnrollment(long userId, String mfaId, MfaSecretCipher.EncryptedSecret encrypted) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        requireEncrypted(encrypted);
        try {
            if (users.findAnyForUpdate(userId) == null) return false;
            UserMfaEntity byId = mfaRecords.findById(boundMfaId);
            if (byId != null && byId.userId() != userId) return false;
            UserMfaEntity existing = mfaRecords.findByUserForUpdate(userId);
            if (existing != null && existing.enabled()) return false;
            if (existing == null) {
                mfaRecords.persistAndFlush(new UserMfaEntity(boundMfaId, userId, "TOTP",
                        encrypted.ciphertext(), encrypted.nonce(), encrypted.keyVersion()));
            } else if (existing.id().equals(boundMfaId)) {
                existing.replacePendingSecret(encrypted.ciphertext(), encrypted.nonce(), encrypted.keyVersion());
            } else {
                mfaRecords.delete(existing);
                mfaRecords.persistAndFlush(new UserMfaEntity(boundMfaId, userId, "TOTP",
                        encrypted.ciphertext(), encrypted.nonce(), encrypted.keyVersion()));
            }
            return true;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not save MFA enrollment", e);
        }
    }

    /** 读取指定用户的 TOTP 密文和验证状态；不返回明文密钥。 */
    @Transactional
    public Optional<StoredMfa> find(long userId, String mfaId) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        UserMfaEntity stored = mfaRecords.findByUserAndId(userId, boundMfaId);
        return stored == null ? Optional.empty() : Optional.of(toStored(stored));
    }

    /** 原子接受一个 TOTP 时间步；行锁保护时间步和失败状态。 */
    @Transactional
    public boolean acceptTotp(long userId, String mfaId, long candidateStep, boolean enrollmentVerification) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        if (candidateStep < 0) throw new IllegalArgumentException("candidateStep must be non-negative");
        UserMfaEntity stored = mfaRecords.findForUpdate(userId, boundMfaId);
        return stored != null && stored.acceptStep(candidateStep, Instant.now(), enrollmentVerification);
    }

    /** 在一个事务内完成 enrollment，锁顺序为用户、认证请求、MFA 状态和恢复码。 */
    @Transactional
    public boolean completeEnrollment(long userId, String challengeId, String clientId, String sessionId,
                                      String mfaId, long candidateStep, String batchId, List<String> hashes) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        String boundBatchId = normalizeMfaId(batchId);
        if (candidateStep < 0) throw new IllegalArgumentException("candidateStep must be non-negative");
        validateRecoveryHashes(hashes);
        try {
            if (users.findAnyForUpdate(userId) == null) return false;
            var challenge = challenges.lockActiveForUpdate(challengeId, userId, clientId,
                    MfaChallengeRepository.Purpose.ENROLL, sessionId);
            if (challenge.isEmpty()) return false;
            UserMfaEntity stored = mfaRecords.findForUpdate(userId, boundMfaId);
            Instant now = Instant.now();
            if (stored == null || stored.enabled() || !stored.canAcceptStep(candidateStep, now, true)) return false;
            if (!challenges.consumeLocked(challenge.get())) return false;
            if (!stored.acceptStep(candidateStep, now, true)) return false;
            replaceRecoveryCodesLocked(userId, boundBatchId, hashes);
            stored.enable(now);
            return true;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not complete MFA enrollment", e);
        }
    }

    /** 在一个事务内接受登录 TOTP 并消费对应认证请求。 */
    @Transactional
    public boolean consumeLoginTotp(long userId, String challengeId, String clientId, String codeSessionId,
                                    String mfaId, long candidateStep) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        if (candidateStep < 0) throw new IllegalArgumentException("candidateStep must be non-negative");
        return consumeLoginFactor(userId, challengeId, clientId, codeSessionId, boundMfaId, candidateStep, null);
    }

    /** 在一个事务内消费登录恢复码并消费对应认证请求。 */
    @Transactional
    public boolean consumeLoginRecovery(long userId, String challengeId, String clientId, String codeSessionId,
                                        String mfaId, String hash) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        if (hash == null || !hash.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid recovery code hash");
        return consumeLoginFactor(userId, challengeId, clientId, codeSessionId, boundMfaId, null, hash);
    }

    /** 统一执行登录因子事务，锁顺序为用户、认证请求、MFA 状态和恢复码。 */
    @Transactional
    boolean consumeLoginFactor(long userId, String challengeId, String clientId, String sessionId,
                               String mfaId, Long candidateStep, String recoveryHash) {
        try {
            if (users.findAnyForUpdate(userId) == null) return false;
            var challenge = challenges.lockActiveForUpdate(challengeId, userId, clientId,
                    MfaChallengeRepository.Purpose.LOGIN, sessionId);
            if (challenge.isEmpty()) return false;
            UserMfaEntity stored = mfaRecords.findForUpdate(userId, mfaId);
            if (stored == null || !stored.enabled()) return false;
            Instant now = Instant.now();
            MfaRecoveryCodeEntity recovery = null;
            if (candidateStep != null) {
                if (!stored.canAcceptStep(candidateStep, now, false)) return false;
            } else {
                recovery = recoveryCodes.findForUpdate(userId, recoveryHash);
                if (recovery == null || recovery.usedAt() != null) return false;
            }
            if (!challenges.consumeLocked(challenge.get())) return false;
            if (candidateStep != null) return stored.acceptStep(candidateStep, now, false);
            return recovery.consume(now);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not consume MFA login factor", e);
        }
    }

    /** 记录一次失败验证；达到阈值时设置短时锁定。 */
    @Transactional
    public boolean recordFailure(long userId, String mfaId) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        UserMfaEntity stored = mfaRecords.findForUpdate(userId, boundMfaId);
        return stored != null && stored.recordFailure(Instant.now(), MAX_FAILURES, LOCK_SECONDS);
    }

    /** 只有已成功接受 enrollment 时间步的待启用记录才能启用。 */
    @Transactional
    public boolean enableEnrollment(long userId, String mfaId) {
        requireUser(userId);
        String boundMfaId = normalizeMfaId(mfaId);
        UserMfaEntity stored = mfaRecords.findForUpdate(userId, boundMfaId);
        if (stored == null || stored.enabled() || stored.lastAcceptedStep() == null) return false;
        stored.enable(Instant.now());
        return true;
    }

    /** 只有已经完成 enrollment 的用户才能进入强制 MFA 策略。 */
    @Transactional
    public boolean setRequired(long userId, boolean required) {
        requireUser(userId);
        ApiKeyUserEntity user = users.findAnyForUpdate(userId);
        if (user == null) return false;
        if (required) {
            UserMfaEntity mfa = mfaRecords.findByUser(userId);
            if (mfa == null || !mfa.enabled()) return false;
        }
        user.setMfaRequired(required);
        return true;
    }

    /** 在一个事务内替换旧恢复码批次；数据库只保存哈希。 */
    @Transactional
    public void replaceRecoveryCodes(long userId, String batchId, List<String> hashes) {
        requireUser(userId);
        String boundBatchId = normalizeMfaId(batchId);
        validateRecoveryHashes(hashes);
        try {
            if (users.findAnyForUpdate(userId) == null) throw new IllegalStateException("user not found");
            replaceRecoveryCodesLocked(userId, boundBatchId, hashes);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Could not replace MFA recovery codes", e);
        }
    }

    /** 使用行锁消费恢复码，同一恢复码只能成功一次。 */
    @Transactional
    public boolean consumeRecoveryCode(long userId, String hash) {
        requireUser(userId);
        if (hash == null || !hash.matches("[0-9a-f]{64}")) throw new IllegalArgumentException("invalid recovery code hash");
        MfaRecoveryCodeEntity code = recoveryCodes.findForUpdate(userId, hash);
        return code != null && code.consume(Instant.now());
    }

    private void replaceRecoveryCodesLocked(long userId, String batchId, List<String> hashes) {
        recoveryCodes.deleteByUser(userId);
        for (String hash : hashes) {
            recoveryCodes.persist(new MfaRecoveryCodeEntity(UUID.randomUUID().toString(), userId, batchId, hash));
        }
    }

    private static StoredMfa toStored(UserMfaEntity stored) {
        var encrypted = new MfaSecretCipher.EncryptedSecret(stored.secretNonce(), stored.secretCiphertext(), stored.keyVersion());
        return new StoredMfa(stored.id(), stored.userId(), encrypted, stored.enabled(),
                stored.lastAcceptedStep(), stored.lockedUntil());
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

    private static void validateRecoveryHashes(List<String> hashes) {
        if (hashes == null || hashes.isEmpty() || hashes.stream().anyMatch(value -> value == null || !value.matches("[0-9a-f]{64}"))) {
            throw new IllegalArgumentException("invalid recovery code hashes");
        }
    }

    public record MfaStatus(long userId, boolean required, String mfaId, boolean enabled) {
    }

    /** 数据库中的 MFA 记录只携带密文和状态字段。 */
    public record StoredMfa(String id, long userId, MfaSecretCipher.EncryptedSecret encrypted,
                            boolean enabled, Long lastAcceptedStep, Instant lockedUntil) {
    }
}
