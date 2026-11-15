package app.keystone.auth;

import app.keystone.audit.LoginLogRepository;
import app.keystone.user.UserRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

/** 在同一事务内完成 MFA 校验、会话占用和 AAL2 令牌签发。 */
@ApplicationScoped
public class MfaLoginService {
    @Inject UserRepository users;
    @Inject MfaService mfa;
    @Inject SessionRepository sessions;
    @Inject MfaSessionRepository mfaSessions;
    @Inject AccessTokenService tokens;
    @Inject LoginLogRepository loginLogs;

    /** 活动会话冲突时抛出异常，让认证请求和一次性 challenge 一起回滚。 */
    @Transactional
    public Result complete(String username, String challengeId, String clientId, String code,
                           boolean forceLogin, String clientAddress, String userAgent) {
        var user = users.findAuthUserByUsername(username.trim()).orElse(null);
        if (user == null) return Result.invalid();

        var verification = mfa.verifyLogin(user.id(), challengeId, clientId, code, clientAddress).orElse(null);
        if (verification == null) return Result.invalid();

        var refresh = sessions.create(user.id(), forceLogin, clientId);
        if (refresh.isEmpty()) throw new ActiveSessionConflict(user.username());

        var created = refresh.get();
        if (!mfaSessions.markVerified(created.sessionId(), user.id(), created.clientId(),
                verification.assurance(), verification.amr())) {
            throw new IllegalStateException("authentication state is unavailable");
        }

        AuthResource.TokenResponse token;
        try {
            token = tokens.issue(user, created.refreshToken(), created.accessTokenId(), created.sessionId(),
                    created.clientId(), created.approvedScope(), created.refreshExpiresAt(),
                    verification.assurance(), verification.amr());
        } catch (IllegalStateException error) {
            throw new TokenUnavailable(created.sessionId(), error);
        }

        users.markLogin(user.id(), clientAddress);
        loginLogs.record(user.username(), "SUCCESS", clientAddress, "MFA login successful", userAgent);
        return Result.success(token);
    }

    /** 供登录资源层区分 MFA challenge 无效和会话冲突。 */
    public record Result(boolean valid, AuthResource.TokenResponse token) {
        static Result invalid() { return new Result(false, null); }

        static Result success(AuthResource.TokenResponse token) { return new Result(true, token); }
    }

    public static final class ActiveSessionConflict extends RuntimeException {
        private final String username;

        ActiveSessionConflict(String username) {
            this.username = username;
        }

        String username() { return username; }
    }

    public static final class TokenUnavailable extends RuntimeException {
        private final String sessionId;

        TokenUnavailable(String sessionId, Throwable cause) {
            super(cause);
            this.sessionId = sessionId;
        }

        String sessionId() { return sessionId; }
    }
}
