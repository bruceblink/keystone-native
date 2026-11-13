package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 使用部署级 AES-256-GCM 密钥保护 TOTP 密钥。
 * 主密钥只从受控配置读取；未启用 MFA 时不会强制解码，避免启动阶段锁死现有用户。
 */
@ApplicationScoped
public class MfaSecretCipher {
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private final String encodedMasterKey;
    private final int masterKeyVersion;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public MfaSecretCipher(
            @ConfigProperty(name = "keystone.security.mfa.master-key", defaultValue = "") String encodedMasterKey,
            @ConfigProperty(name = "keystone.security.mfa.master-key-version", defaultValue = "1") int masterKeyVersion) {
        this.encodedMasterKey = encodedMasterKey == null ? "" : encodedMasterKey.trim();
        if (masterKeyVersion <= 0) throw new IllegalArgumentException("MFA master key version must be positive");
        this.masterKeyVersion = masterKeyVersion;
    }

    MfaSecretCipher(String encodedMasterKey) { this(encodedMasterKey, 1); }

    /** 返回当前部署配置的密钥版本，写入 MFA 记录以支持后续轮换。 */
    public int currentKeyVersion() { return masterKeyVersion; }

    /** 加密 TOTP 密钥，并把主体、记录和密钥版本绑定到认证标签。 */
    public EncryptedSecret encrypt(String userId, String mfaId, int keyVersion, String secret) {
        if (userId == null || mfaId == null || mfaId.isBlank() || keyVersion <= 0 || secret == null || secret.isBlank()) throw new IllegalArgumentException("invalid MFA secret input");
        requireConfiguredVersion(keyVersion);
        byte[] nonce = new byte[NONCE_BYTES]; random.nextBytes(nonce);
        try {
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, nonce, aad(userId, mfaId, keyVersion));
            return new EncryptedSecret(nonce, cipher.doFinal(secret.getBytes(StandardCharsets.UTF_8)), keyVersion);
        } catch (Exception e) { throw new IllegalStateException("Could not encrypt MFA secret", e); }
    }

    /** 解密时重新校验主体和版本标签，密文被替换或归属错误时直接失败。 */
    public String decrypt(String userId, String mfaId, EncryptedSecret encrypted) {
        if (encrypted == null || userId == null || mfaId == null || mfaId.isBlank()) throw new IllegalArgumentException("invalid MFA secret input");
        requireConfiguredVersion(encrypted.keyVersion());
        try {
            Cipher cipher = cipher(Cipher.DECRYPT_MODE, encrypted.nonce(), aad(userId, mfaId, encrypted.keyVersion()));
            return new String(cipher.doFinal(encrypted.ciphertext()), StandardCharsets.UTF_8);
        } catch (Exception e) { throw new IllegalStateException("Could not decrypt MFA secret", e); }
    }

    private Cipher cipher(int mode, byte[] nonce, byte[] aad) throws Exception {
        byte[] key = masterKey();
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher;
    }

    private byte[] masterKey() {
        if (encodedMasterKey.isBlank()) throw new IllegalStateException("MFA master key is not configured");
        try {
            byte[] key = Base64.getDecoder().decode(encodedMasterKey);
            if (key.length != KEY_BYTES) throw new IllegalStateException("MFA master key must decode to 32 bytes");
            return key;
        } catch (IllegalArgumentException e) { throw new IllegalStateException("MFA master key is not valid base64", e); }
    }

    private void requireConfiguredVersion(int keyVersion) {
        if (keyVersion != masterKeyVersion) throw new IllegalStateException("MFA master key version is unavailable");
    }

    private static byte[] aad(String userId, String mfaId, int keyVersion) {
        byte[] id = mfaId.getBytes(StandardCharsets.UTF_8);
        byte[] user = app.keystone.identity.UuidValues.toBytes(userId);
        return ByteBuffer.allocate(user.length + Integer.BYTES + id.length).put(user).putInt(keyVersion).put(id).array();
    }

    /** 密文对象只在内存中携带 nonce、密文和版本；访问数组时返回副本。 */
    public record EncryptedSecret(byte[] nonce, byte[] ciphertext, int keyVersion) {
        public EncryptedSecret {
            nonce = nonce == null ? new byte[0] : nonce.clone();
            ciphertext = ciphertext == null ? new byte[0] : ciphertext.clone();
            if (nonce.length != NONCE_BYTES || ciphertext.length == 0 || keyVersion <= 0) throw new IllegalArgumentException("invalid encrypted MFA secret");
        }
        @Override public byte[] nonce() { return nonce.clone(); }
        @Override public byte[] ciphertext() { return ciphertext.clone(); }
    }
}
