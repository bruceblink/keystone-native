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

/** 持久化 JWT 公钥目录；只保存公开 JWK 字段，不保存签名私钥。 */
@Entity
@Table(name = "sys_jwt_key_registry")
public class JwtKeyRegistryEntity {
    @Id
    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID id;

    @Column(name = "key_id", nullable = false, unique = true, length = 128)
    private String keyId;

    @Column(nullable = false, length = 16)
    private String kty;

    @Column(nullable = false, length = 16)
    private String alg;

    @Column(name = "use_type", nullable = false, length = 16)
    private String useType;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String modulus;

    @Column(nullable = false, length = 128)
    private String exponent;

    @Column(nullable = false, length = 16)
    private String state;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "retired_at")
    private Instant retiredAt;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false, insertable = false, updatable = false)
    private Instant updatedAt;

    protected JwtKeyRegistryEntity() {
    }

    JwtKeyRegistryEntity(String keyId, String modulus, String exponent, String state, Instant expiresAt) {
        this.id = UuidValues.v7Uuid();
        this.keyId = RegistryState.requireKeyId(keyId);
        this.kty = "RSA";
        this.alg = "RS256";
        this.useType = "sig";
        this.modulus = RegistryState.requireValue(modulus, "modulus");
        this.exponent = RegistryState.requireValue(exponent, "exponent");
        this.state = RegistryState.requireState(state);
        this.expiresAt = expiresAt;
    }

    String keyId() { return keyId; }
    String modulus() { return modulus; }
    String exponent() { return exponent; }
    String state() { return state; }
    Instant expiresAt() { return expiresAt; }

    void refresh(String modulus, String exponent, String nextState, Instant nextExpiry) {
        this.modulus = RegistryState.requireValue(modulus, "modulus");
        this.exponent = RegistryState.requireValue(exponent, "exponent");
        this.state = RegistryState.requireState(nextState);
        this.expiresAt = nextExpiry;
    }

    void retire(Instant at, Instant expiry) {
        this.state = RegistryState.RETIRING;
        this.retiredAt = at;
        this.expiresAt = expiry;
    }
}
