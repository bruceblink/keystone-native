package app.keystone.auth;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证普通密码兼容路径和与 Phoenix 一致的 RSA/PKCS#1 登录输入。 */
class LoginPasswordDecoderTest {
    @Test
    void keepsShortPlaintextPasswordsCompatibleWithoutLoadingKey() {
        assertEquals("password", new LoginPasswordDecoder("").decode("password").orElseThrow());
    }

    @Test
    void decryptsBase64RsaPkcs1Password() throws Exception {
        PublicKey publicKey = publicKey();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        String encrypted = Base64.getEncoder().encodeToString(cipher.doFinal("Strong!123".getBytes(StandardCharsets.UTF_8)));

        assertEquals("Strong!123", new LoginPasswordDecoder("keys/privateKey.pem").decode(encrypted).orElseThrow());
    }

    @Test
    void rejectsMalformedRsaCiphertextAsInvalidPassword() {
        String malformed = Base64.getEncoder().encodeToString(new byte[256]);
        assertTrue(new LoginPasswordDecoder("keys/privateKey.pem").decode(malformed).isEmpty());
    }

    private static PublicKey publicKey() throws Exception {
        String pem = Files.readString(Path.of("src/test/resources/keys/publicKey.pem"));
        String body = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(body)));
    }
}
