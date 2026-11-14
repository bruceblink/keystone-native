package app.keystone.auth;

import app.keystone.identity.UuidValues;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/** 保存 OIDC 授权请求的短期状态；回调前仅保留服务端生成的 PKCE verifier。 */
@Entity
@Table(name = "sys_oidc_auth_request")
public class OidcAuthRequestEntity {
    @Id @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;
    @Column(name = "state_hash", nullable = false, unique = true, length = 64) private String stateHash;
    @Column(name = "nonce_hash", nullable = false, length = 64) private String nonceHash;
    @Column(name = "code_challenge", nullable = false, length = 128) private String codeChallenge;
    @Column(name = "code_verifier", nullable = false, length = 128) private String codeVerifier;
    @Column(name = "code_challenge_method", nullable = false, length = 16) private String codeChallengeMethod;
    @Column(name = "client_id", nullable = false, length = 128) private String clientId;
    @Column(name = "redirect_uri", nullable = false, length = 1024) private String redirectUri;
    @Column(name = "expires_at", nullable = false) private Instant expiresAt;
    @Column(name = "consumed_at") private Instant consumedAt;
    @Column(name = "created_at", nullable = false, insertable = false, updatable = false) private Instant createdAt;

    protected OidcAuthRequestEntity() {}

    OidcAuthRequestEntity(String stateHash, String nonceHash, String codeChallenge, String codeVerifier, String clientId,
                          String redirectUri, Instant expiresAt) {
        this.id = UuidValues.v7Uuid();
        this.stateHash = stateHash;
        this.nonceHash = nonceHash;
        this.codeChallenge = codeChallenge;
        this.codeVerifier = codeVerifier;
        this.codeChallengeMethod = "S256";
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.expiresAt = expiresAt;
    }

    String stateHash() { return stateHash; }
    String nonceHash() { return nonceHash; }
    String codeChallenge() { return codeChallenge; }
    String codeVerifier() { return codeVerifier; }
    String clientId() { return clientId; }
    String redirectUri() { return redirectUri; }
    Instant expiresAt() { return expiresAt; }
    Instant consumedAt() { return consumedAt; }
    void consume(Instant at) { consumedAt = at; }
}
