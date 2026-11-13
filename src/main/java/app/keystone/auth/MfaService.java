package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * 编排管理员 TOTP 的 enrollment、登录验证请求和策略状态。
 *
 * <p>本服务不记录密码、TOTP 明文或恢复码。认证请求状态、密文和一次性消费分别交给
 * 对应仓储处理；数据库异常直接向资源层传播为失败关闭。</p>
 */
@ApplicationScoped
public class MfaService {
    private static final Logger LOG = Logger.getLogger(MfaService.class);
    private static final String ASSURANCE = "AAL2";
    private static final String TOTP_AMR = "otp";
    private static final String RECOVERY_AMR = "recovery";

    @Inject MfaRepository mfa;
    @Inject MfaChallengeRepository challenges;
    @Inject MfaSecretCipher secrets;
    @Inject TotpService totp;
    @Inject MfaRecoveryCodeService recoveryCodes;
    @Inject MfaRateLimiter rateLimiter;
    @ConfigProperty(name = "keystone.security.mfa.challenge-lifetime-seconds", defaultValue = "300")
    long challengeLifetimeSeconds;
    @ConfigProperty(name = "keystone.security.mfa.issuer", defaultValue = "Keystone")
    String issuer;

    /** 根据用户策略决定密码成功后是否需要第二因素。 */
    public LoginPreparation prepareLogin(long userId, String clientId) {
        String boundClientId = normalizeClientId(clientId);
        var status = status(userId);
        if (!status.required()) return new LoginPreparation(false, null);
        if (!status.enabled() || status.mfaId() == null) return new LoginPreparation(true, null);
        var challenge = challenges.create(userId, MfaChallengeRepository.Purpose.LOGIN, boundClientId,
                null, null, expiresAt());
        return new LoginPreparation(true, new LoginChallenge(challenge.id(), boundClientId, challenge.expiresAt()));
    }

    /** 为当前人类会话创建待验证 enrollment，并只返回一次 TOTP 配置材料。 */
    public Enrollment beginEnrollment(long userId, String username, String clientId, String sessionId) {
        String boundClientId = normalizeClientId(clientId);
        String boundSessionId = requiredSessionId(sessionId);
        var status = status(userId);
        if (status.enabled()) throw new IllegalStateException("MFA is already enabled");
        // 在写入待验证密文前检查恢复码 pepper，避免完成 enrollment 后无法生成恢复码。
        recoveryCodes.generateBatch();
        String mfaId = UUID.randomUUID().toString();
        String secret = totp.generateSecret();
        var encrypted = secrets.encrypt(userId, mfaId, secrets.currentKeyVersion(), secret);
        if (!mfa.replacePendingEnrollment(userId, mfaId, encrypted)) throw new IllegalStateException("MFA enrollment could not be started");
        var challenge = challenges.create(userId, MfaChallengeRepository.Purpose.ENROLL, boundClientId,
                boundSessionId, null, expiresAt());
        return new Enrollment(challenge.id(), mfaId, secret, otpauthUri(username, secret), challenge.expiresAt());
    }

    /** 校验 enrollment TOTP，启用 MFA，并返回只展示一次的恢复码。 */
    public Optional<EnrollmentResult> verifyEnrollment(long userId, String challengeId, String clientId,
                                                        String sessionId, String code) {
        return verifyEnrollment(userId, challengeId, clientId, sessionId, code, null);
    }

    /** 带来源地址的 enrollment 校验；主体和地址失败次数同时受限。 */
    public Optional<EnrollmentResult> verifyEnrollment(long userId, String challengeId, String clientId,
                                                        String sessionId, String code, String ipAddress) {
        String boundClientId = normalizeClientId(clientId);
        String boundSessionId = requiredSessionId(sessionId);
        if (rateLimiter.isBlocked(userId, ipAddress)) return Optional.empty();
        var challenge = challenges.findActive(challengeId, userId, boundClientId,
                MfaChallengeRepository.Purpose.ENROLL, boundSessionId);
        var status = status(userId);
        if (challenge.isEmpty() || status.mfaId() == null || status.enabled()) return Optional.empty();
        var stored = mfa.find(userId, status.mfaId()).orElse(null);
        if (stored == null) return Optional.empty();
        String secret = secrets.decrypt(userId, stored.id(), stored.encrypted());
        var step = matchingStep(secret, code);
        if (step.isEmpty()) {
            recordFailure(challengeId, userId, boundClientId, MfaChallengeRepository.Purpose.ENROLL, boundSessionId, stored.id(), ipAddress);
            return Optional.empty();
        }
        var batch = recoveryCodes.generateBatch();
        var hashes = batch.codes().stream().map(recoveryCodes::hash).toList();
        if (!mfa.completeEnrollment(userId, challengeId, boundClientId, boundSessionId, stored.id(),
                step.getAsLong(), batch.batchId(), hashes)) {
            return Optional.empty();
        }
        clearRateLimitAfterSuccess(userId, ipAddress);
        return Optional.of(new EnrollmentResult(batch.codes()));
    }

    /** 校验登录验证请求；成功后调用方才可以创建刷新会话和访问令牌。 */
    public Optional<LoginVerification> verifyLogin(long userId, String challengeId, String clientId, String code) {
        return verifyLogin(userId, challengeId, clientId, code, null);
    }

    /** 带来源地址的登录验证请求校验；主体和地址失败次数同时受限。 */
    public Optional<LoginVerification> verifyLogin(long userId, String challengeId, String clientId, String code, String ipAddress) {
        String boundClientId = normalizeClientId(clientId);
        if (rateLimiter.isBlocked(userId, ipAddress)) return Optional.empty();
        var challenge = challenges.findActive(challengeId, userId, boundClientId,
                MfaChallengeRepository.Purpose.LOGIN, null);
        var status = status(userId);
        if (challenge.isEmpty()) {
            rateLimiter.recordFailure(userId, ipAddress);
            return Optional.empty();
        }
        if (!status.required() || !status.enabled() || status.mfaId() == null) return Optional.empty();
        var stored = mfa.find(userId, status.mfaId()).orElse(null);
        if (stored == null) {
            rateLimiter.recordFailure(userId, ipAddress);
            return Optional.empty();
        }
        String secret = secrets.decrypt(userId, stored.id(), stored.encrypted());
        var step = matchingStep(secret, code);
        if (step.isPresent() && mfa.consumeLoginTotp(userId, challengeId, boundClientId, null,
                stored.id(), step.getAsLong())) {
            clearRateLimitAfterSuccess(userId, ipAddress);
            return Optional.of(new LoginVerification(ASSURANCE, TOTP_AMR));
        }
        try {
            String hash = recoveryCodes.hash(code);
            if (mfa.consumeLoginRecovery(userId, challengeId, boundClientId, null, stored.id(), hash)) {
                clearRateLimitAfterSuccess(userId, ipAddress);
                return Optional.of(new LoginVerification(ASSURANCE, RECOVERY_AMR));
            }
        } catch (IllegalArgumentException ignored) {
            // 格式错误与错误验证码统一走失败路径，不向客户端暴露验证分支。
        }
        recordFailure(challengeId, userId, boundClientId, MfaChallengeRepository.Purpose.LOGIN, null, stored.id(), ipAddress);
        return Optional.empty();
    }

    /** 只有已完成 enrollment 的用户才能进入强制 MFA 策略。 */
    public boolean setRequired(long userId, boolean required) {
        return mfa.setRequired(userId, required);
    }

    /** 生成新恢复码批次并原子替换旧批次；调用方只应返回本次明文结果。 */
    public java.util.List<String> rotateRecoveryCodes(long userId) {
        var status = status(userId);
        if (!status.enabled()) throw new IllegalStateException("MFA is not enabled");
        var batch = recoveryCodes.generateBatch();
        mfa.replaceRecoveryCodes(userId, batch.batchId(), batch.codes().stream().map(recoveryCodes::hash).toList());
        return batch.codes();
    }

    private MfaRepository.MfaStatus status(long userId) {
        return mfa.findStatus(userId).orElseThrow(() -> new IllegalArgumentException("user not found"));
    }

    private void recordFailure(String challengeId, long userId, String clientId, MfaChallengeRepository.Purpose purpose,
                               String sessionId, String mfaId, String ipAddress) {
        mfa.recordFailure(userId, mfaId);
        challenges.recordFailure(challengeId, userId, clientId, purpose, sessionId);
        rateLimiter.recordFailure(userId, ipAddress);
    }

    /** 因子消费已经成功后，限流清理失败只记录主体和结果，不把成功响应改成失败。 */
    private void clearRateLimitAfterSuccess(long userId, String ipAddress) {
        try { rateLimiter.clear(userId, ipAddress); }
        catch (IllegalStateException e) { LOG.warnf(e, "MFA rate-limit cleanup failed after successful factor userId=%d", userId); }
    }

    private java.util.OptionalLong matchingStep(String secret, String code) {
        return totp.matchingStep(secret, code, Instant.now().getEpochSecond());
    }

    private Instant expiresAt() {
        if (challengeLifetimeSeconds < 60 || challengeLifetimeSeconds > 600) {
            throw new IllegalStateException("MFA challenge lifetime must be between 60 and 600 seconds");
        }
        return Instant.now().plus(Duration.ofSeconds(challengeLifetimeSeconds));
    }

    private String otpauthUri(String username, String secret) {
        String safeIssuer = issuer == null || issuer.isBlank() ? "Keystone" : issuer.trim();
        String label = safeIssuer + ":" + (username == null || username.isBlank() ? "user" : username.trim());
        return "otpauth://totp/" + encode(label) + "?secret=" + encode(secret) + "&issuer=" + encode(safeIssuer)
                + "&algorithm=SHA1&digits=6&period=30";
    }

    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }

    private static String normalizeClientId(String value) {
        String normalized = value == null || value.isBlank() ? SessionRepository.DEFAULT_CLIENT_ID : value.trim().toLowerCase(java.util.Locale.ROOT);
        if (!normalized.matches("[a-z0-9][a-z0-9._-]{0,63}")) throw new IllegalArgumentException("invalid clientId");
        return normalized;
    }

    private static String requiredSessionId(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("sessionId is required");
        String normalized = value.trim();
        try { return UUID.fromString(normalized).toString(); }
        catch (IllegalArgumentException e) { throw new IllegalArgumentException("sessionId must be a UUID", e); }
    }

    public record LoginPreparation(boolean required, LoginChallenge challenge) {}
    public record LoginChallenge(String challengeId, String clientId, Instant expiresAt) {}
    public record Enrollment(String challengeId, String mfaId, String secret, String otpauthUri, Instant expiresAt) {}
    public record EnrollmentResult(java.util.List<String> recoveryCodes) {}
    public record LoginVerification(String assurance, String amr) {}
}
