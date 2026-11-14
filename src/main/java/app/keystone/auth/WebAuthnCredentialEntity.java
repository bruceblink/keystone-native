package app.keystone.auth;

import io.quarkus.security.webauthn.WebAuthnCredentialRecord;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.UUID;

/** 保存 WebAuthn 凭据的公开验证材料；认证器私钥不会进入服务端。 */
@Entity
@Table(name = "sys_webauthn_credential")
public class WebAuthnCredentialEntity {
    @Id
    @Column(name = "credential_id", length = 512, nullable = false)
    private String credentialId;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(name = "user_id", columnDefinition = "BINARY(16)", nullable = false, length = 16)
    private UUID userId;

    @Column(nullable = false, length = 64)
    private String username;

    @JdbcTypeCode(SqlTypes.VARBINARY)
    @Column(name = "public_key", nullable = false, length = 4096, columnDefinition = "VARBINARY(4096)")
    private byte[] publicKey;

    @Column(name = "public_key_algorithm", nullable = false)
    private long publicKeyAlgorithm;

    @Column(nullable = false)
    private long counter;

    @JdbcTypeCode(SqlTypes.BINARY)
    @Column(columnDefinition = "BINARY(16)", length = 16)
    private UUID aaguid;

    @Column(length = 128)
    private String transports;

    protected WebAuthnCredentialEntity() {
    }

    WebAuthnCredentialEntity(WebAuthnCredentialRecord record, UUID userId, String username) {
        var data = record.getRequiredPersistedData();
        this.credentialId = data.credentialId();
        this.userId = userId;
        this.username = username;
        this.publicKey = data.publicKey().clone();
        this.publicKeyAlgorithm = data.publicKeyAlgorithm();
        this.counter = data.counter();
        this.aaguid = data.aaguid();
    }

    String credentialId() {
        return credentialId;
    }

    String username() {
        return username;
    }

    long counter() {
        return counter;
    }

    void updateCounter(long nextCounter) {
        counter = nextCounter;
    }

    WebAuthnCredentialRecord toRecord() {
        return WebAuthnCredentialRecord.fromRequiredPersistedData(
                new WebAuthnCredentialRecord.RequiredPersistedData(
                        username, credentialId, aaguid, publicKey.clone(), publicKeyAlgorithm, counter));
    }
}
