package app.keystone.user;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 统一校验用户密码策略。
 *
 * <p>策略只在设置或修改密码时执行。校验失败只返回通用原因，不记录密码和详细命中规则。</p>
 */
@ApplicationScoped
public class PasswordPolicy {
    private final int minLength;
    private final boolean requireUppercase;
    private final boolean requireLowercase;
    private final boolean requireDigit;
    private final boolean requireSpecial;
    private final Set<String> disallowed;

    @Inject
    public PasswordPolicy(
            @ConfigProperty(name = "keystone.security.password.min-length", defaultValue = "12") int minLength,
            @ConfigProperty(name = "keystone.security.password.require-uppercase", defaultValue = "true") boolean requireUppercase,
            @ConfigProperty(name = "keystone.security.password.require-lowercase", defaultValue = "true") boolean requireLowercase,
            @ConfigProperty(name = "keystone.security.password.require-digit", defaultValue = "true") boolean requireDigit,
            @ConfigProperty(name = "keystone.security.password.require-special", defaultValue = "true") boolean requireSpecial,
            @ConfigProperty(name = "keystone.security.password.disallowed", defaultValue = "password,password1,1234567890,qwerty123,admin") String disallowed) {
        this.minLength = minLength;
        this.requireUppercase = requireUppercase;
        this.requireLowercase = requireLowercase;
        this.requireDigit = requireDigit;
        this.requireSpecial = requireSpecial;
        this.disallowed = parseDisallowed(disallowed);
    }

    PasswordPolicy(int minLength, boolean requireUppercase, boolean requireLowercase,
                   boolean requireDigit, boolean requireSpecial, Collection<String> disallowed) {
        this(minLength, requireUppercase, requireLowercase, requireDigit, requireSpecial,
                disallowed == null ? Set.of() : disallowed.stream()
                        .map(value -> value.toLowerCase(Locale.ROOT))
                        .collect(Collectors.toUnmodifiableSet()));
    }

    private PasswordPolicy(int minLength, boolean requireUppercase, boolean requireLowercase,
                           boolean requireDigit, boolean requireSpecial, Set<String> disallowed) {
        this.minLength = minLength;
        this.requireUppercase = requireUppercase;
        this.requireLowercase = requireLowercase;
        this.requireDigit = requireDigit;
        this.requireSpecial = requireSpecial;
        this.disallowed = Set.copyOf(disallowed);
    }

    /** 校验密码和用户名关系；密码内容不会进入日志或异常消息。 */
    public void validate(String username, String password) {
        validateConfiguration();
        if (password == null || password.isBlank()) throw invalid();
        int length = password.codePointCount(0, password.length());
        if (length < minLength) throw invalid();
        String lowerPassword = password.toLowerCase(Locale.ROOT);
        if (disallowed.contains(lowerPassword)) throw invalid();
        if (username != null && !username.isBlank()) {
            String lowerUsername = username.trim().toLowerCase(Locale.ROOT);
            if (lowerUsername.length() >= 4 && lowerPassword.contains(lowerUsername)) throw invalid();
        }
        if (requireUppercase && password.codePoints().noneMatch(Character::isUpperCase)) throw invalid();
        if (requireLowercase && password.codePoints().noneMatch(Character::isLowerCase)) throw invalid();
        if (requireDigit && password.codePoints().noneMatch(Character::isDigit)) throw invalid();
        if (requireSpecial && password.codePoints().noneMatch(value -> !Character.isLetterOrDigit(value))) throw invalid();
    }

    /** 返回策略的固定摘要，供输入边界测试使用，不包含配置中的禁用密码。 */
    String requirements() {
        validateConfiguration();
        return "minLength=" + minLength + ",uppercase=" + requireUppercase + ",lowercase="
                + requireLowercase + ",digit=" + requireDigit + ",special=" + requireSpecial;
    }

    private void validateConfiguration() {
        if (minLength < 8 || minLength > 256) throw new IllegalStateException("password policy min-length must be between 8 and 256");
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("password does not meet security policy");
    }

    private static Set<String> parseDisallowed(String value) {
        if (value == null || value.isBlank()) return Set.of();
        return Arrays.stream(value.split(","))
                .map(String::trim)
                .filter(item -> !item.isBlank())
                .map(item -> item.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }
}
