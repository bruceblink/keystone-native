package app.keystone.auth;

import app.keystone.user.UserRepository;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;

@ApplicationScoped
public class AccessTokenService {
    private static final Duration ACCESS_LIFETIME = Duration.ofMinutes(5);
    @Inject ApiKeyUserRepository users;
    @ConfigProperty(name = "mp.jwt.verify.issuer") String issuer;
    @ConfigProperty(name = "mp.jwt.verify.audiences", defaultValue = "keystone-api") String audience;
    @ConfigProperty(name = "keystone.security.jwt.key-id", defaultValue = "") String keyId;

    public AuthResource.TokenResponse issue(UserRepository.AuthUser user, String refreshToken, String accessTokenId, String sessionId, Instant refreshExpiresAt) {
        return issue(user, refreshToken, accessTokenId, sessionId, SessionRepository.DEFAULT_CLIENT_ID, refreshExpiresAt);
    }

    /** 将会话客户端写入访问令牌，供资源服务记录和诊断当前会话边界。 */
    public AuthResource.TokenResponse issue(UserRepository.AuthUser user, String refreshToken, String accessTokenId, String sessionId, String clientId, Instant refreshExpiresAt) {
        return issue(user, refreshToken, accessTokenId, sessionId, clientId, null, refreshExpiresAt);
    }

    /** 刷新会话只能在创建时批准的权限范围内发行访问令牌。 */
    public AuthResource.TokenResponse issue(UserRepository.AuthUser user, String refreshToken, String accessTokenId, String sessionId, String clientId, String approvedScope, Instant refreshExpiresAt) {
        return issue(user, refreshToken, accessTokenId, sessionId, clientId, approvedScope, refreshExpiresAt, "AAL1", "pwd");
    }

    /**
     * 发行带认证强度的访问令牌；刷新流程使用 AAL1，MFA 登录使用 AAL2。
     * `amr` 只保存已完成的认证方法，不保存验证码或其他秘密材料。
     */
    public AuthResource.TokenResponse issue(UserRepository.AuthUser user, String refreshToken, String accessTokenId,
                                            String sessionId, String clientId, String approvedScope,
                                            Instant refreshExpiresAt, String assurance, String authenticationMethod) {
        Instant expiresAt = Instant.now().plus(ACCESS_LIFETIME);
        java.util.List<String> permissions = new java.util.ArrayList<>(users.permissions(user.id()));
        if (approvedScope != null) {
            var approved = java.util.Set.of(approvedScope.isBlank() ? new String[0] : approvedScope.split(" "));
            permissions = permissions.stream().filter(approved::contains).toList();
        }
        long permissionVersion = users.permissionVersion(user.id());
        String accessToken = Jwt.issuer(issuer)
                .subject(String.valueOf(user.id()))
                .audience(audience)
                .upn(user.username())
                .claim("type", "access")
                .claim("jti", accessTokenId)
                .claim("sid", sessionId)
                .claim("client_id", clientId)
                .claim("permission_version", permissionVersion)
                .claim("aal", normalizeAssurance(assurance))
                .claim("amr", List.of(normalizeAuthenticationMethod(authenticationMethod)))
                .claim("userId", user.id())
                .claim("scope", String.join(" ", permissions))
                .groups(new HashSet<>(user.roles()))
                .issuedAt(Instant.now())
                .expiresAt(expiresAt)
                .jws()
                .keyId(requireKeyId(keyId))
                .sign();
        long refreshSeconds = Math.max(0, Duration.between(Instant.now(), refreshExpiresAt).getSeconds());
        return new AuthResource.TokenResponse(accessToken, refreshToken, "Bearer", ACCESS_LIFETIME.toSeconds(), refreshSeconds, user.username(), user.displayName(), user.roles(), sessionId, clientId);
    }

    /** 验证签名密钥标识，避免发行没有可轮换来源的匿名密钥令牌。 */
    static String requireKeyId(String value) {
        if (value == null || value.isBlank()) throw new IllegalStateException("JWT key id is not configured");
        String normalized = value.trim();
        if (normalized.length() > 128 || !normalized.matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")) {
            throw new IllegalStateException("JWT key id is invalid");
        }
        return normalized;
    }

    private static String normalizeAssurance(String value) {
        if ("AAL1".equals(value) || "AAL2".equals(value)) return value;
        throw new IllegalArgumentException("JWT assurance must be AAL1 or AAL2");
    }

    private static String normalizeAuthenticationMethod(String value) {
        if (value == null || value.isBlank() || !value.matches("[a-z][a-z0-9._:-]{0,31}")) {
            throw new IllegalArgumentException("JWT authentication method is invalid");
        }
        return value;
    }
}
