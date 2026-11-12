package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Locale;
import java.util.OptionalLong;

/**
 * RFC 6238 TOTP 核心服务。
 *
 * <p>服务只负责密钥编码、代码计算和时间窗口验证。重复时间步、失败计数、
 * 锁定和数据库状态由上层认证流程负责；本类不保存密钥，也不记录代码。</p>
 */
@ApplicationScoped
public class TotpService {
    public static final int CODE_DIGITS = 6;
    public static final long TIME_STEP_SECONDS = 30;
    public static final int SECRET_BYTES = 20;
    private static final int WINDOW_STEPS = 1;
    private static final int CODE_MODULUS = 1_000_000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

    /** 生成 160 位随机密钥，并返回无填充的 RFC 4648 Base32 文本。 */
    public String generateSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        return encodeBase32(secret);
    }

    /** 按给定 Unix 秒计算当前时间步的六位 TOTP 代码。 */
    public String code(String base32Secret, long epochSeconds) {
        byte[] secret = decodeSecret(base32Secret);
        long counter = counter(epochSeconds);
        return formatCode(hmac(secret, counter));
    }

    /** 使用当前时间计算代码；生产调用方可以传入固定时间以便验收。 */
    public String code(String base32Secret, Instant instant) {
        if (instant == null) throw new IllegalArgumentException("instant is required");
        return code(base32Secret, instant.getEpochSecond());
    }

    /**
     * 在前一个、当前和后一个时间步内验证代码。
     * 三个候选值都会完成常量时间比较，再合并结果，避免因命中窗口位置提前返回。
     */
    public boolean verify(String base32Secret, String presentedCode, long epochSeconds) {
        return matchingStep(base32Secret, presentedCode, epochSeconds).isPresent();
    }

    /** 返回实际命中的时间步；调用方可用它执行同一时间步的原子重放检查。 */
    public OptionalLong matchingStep(String base32Secret, String presentedCode, long epochSeconds) {
        byte[] secret = decodeSecret(base32Secret);
        if (epochSeconds < 0) throw new IllegalArgumentException("epochSeconds must be non-negative");
        if (!validCode(presentedCode)) return OptionalLong.empty();
        byte[] presented = presentedCode.getBytes(StandardCharsets.US_ASCII);
        boolean matched = false;
        long matchedStep = Long.MIN_VALUE;
        for (int offset = -WINDOW_STEPS; offset <= WINDOW_STEPS; offset++) {
            long candidateTime;
            try {
                candidateTime = Math.addExact(epochSeconds, offset * TIME_STEP_SECONDS);
            } catch (ArithmeticException ignored) {
                continue;
            }
            if (candidateTime < 0) continue;
            byte[] expected = formatCode(hmac(secret, counter(candidateTime))).getBytes(StandardCharsets.US_ASCII);
            boolean equal = MessageDigest.isEqual(expected, presented);
            matched |= equal;
            if (equal) matchedStep = counter(candidateTime);
        }
        return matched ? OptionalLong.of(matchedStep) : OptionalLong.empty();
    }

    /** 使用当前时间验证代码。 */
    public boolean verify(String base32Secret, String presentedCode, Instant instant) {
        if (instant == null) throw new IllegalArgumentException("instant is required");
        return verify(base32Secret, presentedCode, instant.getEpochSecond());
    }

    private static long counter(long epochSeconds) {
        if (epochSeconds < 0) throw new IllegalArgumentException("epochSeconds must be non-negative");
        return epochSeconds / TIME_STEP_SECONDS;
    }

    private static byte[] hmac(byte[] secret, long counter) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            return mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(counter).array());
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA1 is unavailable", e);
        }
    }

    private static String formatCode(byte[] digest) {
        int offset = digest[digest.length - 1] & 0x0f;
        int binary = ((digest[offset] & 0x7f) << 24)
                | ((digest[offset + 1] & 0xff) << 16)
                | ((digest[offset + 2] & 0xff) << 8)
                | (digest[offset + 3] & 0xff);
        return String.format(Locale.ROOT, "%0" + CODE_DIGITS + "d", binary % CODE_MODULUS);
    }

    private static boolean validCode(String value) {
        if (value == null || value.length() != CODE_DIGITS) return false;
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (current < '0' || current > '9') return false;
        }
        return true;
    }

    private static byte[] decodeSecret(String value) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("TOTP secret is required");
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        int paddingStart = normalized.indexOf('=');
        if (paddingStart >= 0) {
            for (int i = paddingStart; i < normalized.length(); i++) {
                if (normalized.charAt(i) != '=') throw new IllegalArgumentException("invalid Base32 TOTP secret");
            }
            normalized = normalized.substring(0, paddingStart);
        }
        int remainder = normalized.length() % 8;
        if (normalized.isEmpty() || remainder == 1 || remainder == 3 || remainder == 6) {
            throw new IllegalArgumentException("invalid Base32 TOTP secret");
        }
        byte[] decoded = new byte[(normalized.length() * 5) / 8];
        int buffer = 0;
        int bits = 0;
        int index = 0;
        for (int i = 0; i < normalized.length(); i++) {
            int valueAt = base32Value(normalized.charAt(i));
            if (valueAt < 0) throw new IllegalArgumentException("invalid Base32 TOTP secret");
            buffer = (buffer << 5) | valueAt;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                decoded[index++] = (byte) (buffer >> bits);
                buffer &= (1 << bits) - 1;
            }
        }
        if (bits > 0 && buffer != 0) throw new IllegalArgumentException("non-zero trailing Base32 bits");
        if (decoded.length < 16) throw new IllegalArgumentException("TOTP secret must contain at least 128 bits");
        return decoded;
    }

    private static int base32Value(char value) {
        if (value >= 'A' && value <= 'Z') return value - 'A';
        if (value >= '2' && value <= '7') return value - '2' + 26;
        return -1;
    }

    private static String encodeBase32(byte[] value) {
        StringBuilder result = new StringBuilder((value.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte current : value) {
            buffer = (buffer << 8) | (current & 0xff);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                result.append(BASE32_ALPHABET[(buffer >> bits) & 0x1f]);
            }
        }
        if (bits > 0) result.append(BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f]);
        return result.toString();
    }
}
