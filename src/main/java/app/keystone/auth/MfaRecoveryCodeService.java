package app.keystone.auth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 生成和校验 MFA 一次性恢复码。
 *
 * <p>本服务只返回 enrollment 阶段需要展示一次的明文恢复码。持久化层只应保存
 * {@link #hash(String)} 返回的摘要，并在数据库事务中原子消费匹配记录。</p>
 */
@ApplicationScoped
public class MfaRecoveryCodeService {
    public static final int CODE_COUNT = 10;
    private static final int CODE_BYTES = 16;
    private static final int CODE_HEX_LENGTH = CODE_BYTES * 2;
    private static final int GROUP_HEX_LENGTH = 4;
    private final SecureRandom random = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of().withUpperCase();
    private final String pepper;

    @Inject
    public MfaRecoveryCodeService(
            @ConfigProperty(name = "keystone.security.mfa.recovery-pepper", defaultValue = "") String pepper) {
        this.pepper = pepper == null ? "" : pepper.trim();
    }

    /** 生成固定数量的恢复码；明文只通过返回值交给 enrollment 响应层。 */
    public RecoveryCodeBatch generateBatch() {
        requirePepper();
        var codes = new java.util.ArrayList<String>(CODE_COUNT);
        Set<String> seen = new HashSet<>(CODE_COUNT);
        while (codes.size() < CODE_COUNT) {
            byte[] bytes = new byte[CODE_BYTES];
            random.nextBytes(bytes);
            String code = format(HEX.formatHex(bytes));
            if (seen.add(code)) codes.add(code);
        }
        return new RecoveryCodeBatch(UUID.randomUUID().toString(), List.copyOf(codes));
    }

    /** 规范化并使用部署级 pepper 计算 HMAC-SHA-256 摘要。 */
    public String hash(String code) {
        String normalized = normalize(code);
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(requirePepper().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return HexFormat.of().formatHex(mac.doFinal(normalized.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA-256 is unavailable", e);
        }
    }

    /** 对输入摘要和恢复码做常量时间比较；格式错误或摘要错误时返回 false。 */
    public boolean matches(String code, String expectedHash) {
        if (expectedHash == null || !expectedHash.matches("[0-9a-fA-F]{64}")) return false;
        try {
            byte[] actual = HexFormat.of().parseHex(hash(code));
            byte[] expected = HexFormat.of().parseHex(expectedHash);
            return MessageDigest.isEqual(actual, expected);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private String requirePepper() {
        if (pepper.isBlank()) throw new IllegalStateException("MFA recovery pepper is not configured");
        return pepper;
    }

    private static String normalize(String code) {
        if (code == null) throw new IllegalArgumentException("recovery code is required");
        String value = code.trim().toUpperCase(Locale.ROOT);
        if (value.matches("[0-9A-F]{32}")) return format(value);
        if (!value.matches("[0-9A-F]{4}(?:-[0-9A-F]{4}){7}")) {
            throw new IllegalArgumentException("invalid MFA recovery code format");
        }
        return value;
    }

    private static String format(String raw) {
        if (raw.length() != CODE_HEX_LENGTH) throw new IllegalArgumentException("invalid MFA recovery code length");
        var result = new StringBuilder(raw.length() + raw.length() / GROUP_HEX_LENGTH - 1);
        for (int offset = 0; offset < raw.length(); offset += GROUP_HEX_LENGTH) {
            if (offset > 0) result.append('-');
            result.append(raw, offset, offset + GROUP_HEX_LENGTH);
        }
        return result.toString();
    }

    /** 批次 ID 用于恢复码轮换和审计；明文列表只应在 enrollment 响应中展示一次。 */
    public record RecoveryCodeBatch(String batchId, List<String> codes) {
        public RecoveryCodeBatch {
            if (batchId == null || batchId.isBlank() || codes == null || codes.size() != CODE_COUNT) {
                throw new IllegalArgumentException("invalid recovery code batch");
            }
            var normalized = codes.stream().map(MfaRecoveryCodeService::normalize).toList();
            if (normalized.stream().distinct().count() != CODE_COUNT) {
                throw new IllegalArgumentException("recovery code batch contains duplicates");
            }
            codes = List.copyOf(normalized);
        }
    }
}
