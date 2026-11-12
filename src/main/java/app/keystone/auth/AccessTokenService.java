package app.keystone.auth;

import app.keystone.user.UserRepository;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;

@ApplicationScoped
public class AccessTokenService {
    private static final Duration ACCESS_LIFETIME = Duration.ofMinutes(5);
    @Inject UserRepository users;
    @ConfigProperty(name = "mp.jwt.verify.issuer") String issuer;
    @ConfigProperty(name = "mp.jwt.verify.audiences", defaultValue = "keystone-api") String audience;

    public AuthResource.TokenResponse issue(UserRepository.AuthUser user, String refreshToken, String accessTokenId, String sessionId, Instant refreshExpiresAt) {
        Instant expiresAt = Instant.now().plus(ACCESS_LIFETIME);
        var permissions = users.permissions(user.id());
        String accessToken = Jwt.issuer(issuer)
                .subject(String.valueOf(user.id()))
                .audience(audience)
                .upn(user.username())
                .claim("jti", accessTokenId)
                .claim("sid", sessionId)
                .claim("userId", user.id())
                .claim("scope", String.join(" ", permissions))
                .groups(new HashSet<>(user.roles()))
                .issuedAt(Instant.now())
                .expiresAt(expiresAt)
                .sign();
        long refreshSeconds = Math.max(0, Duration.between(Instant.now(), refreshExpiresAt).getSeconds());
        return new AuthResource.TokenResponse(accessToken, accessToken, refreshToken, "Bearer", ACCESS_LIFETIME.toSeconds(), refreshSeconds, user.username(), user.displayName(), user.roles());
    }
}
