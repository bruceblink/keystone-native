package app.keystone;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * API 业务错误码目录。
 *
 * <p>错误码是跨后端和前端的稳定标识。HTTP 状态由资源入口决定，目录中的
 * {@link #httpStatus()} 只记录该业务条件的默认状态，不会覆盖调用方的实际状态。
 * {@link #retryable()} 表示调用方是否可以在相同请求上重试；{@link #safeMessage()}
 * 表示响应 message 可以直接展示，敏感异常必须使用安全的固定文案。</p>
 */
public enum ErrorCode {
    INVALID_CREDENTIAL("invalid_credential", 401, "凭据无效或已过期", RetryAdvice.NEVER, "error.invalid_credential", true),
    AUTHENTICATION_REQUIRED("authentication_required", 401, "请求缺少有效认证", RetryAdvice.NEVER, "error.authentication_required", true),
    MFA_REQUIRED("mfa_required", 401, "需要完成多因素认证", RetryAdvice.AFTER_CORRECTION, "error.mfa_required", true),
    MFA_STEP_UP_REQUIRED("mfa_step_up_required", 403, "需要完成当前操作的多因素认证升级", RetryAdvice.AFTER_CORRECTION, "error.mfa_step_up_required", true),
    MFA_INVALID_CODE("mfa_invalid_code", 401, "多因素认证验证码无效", RetryAdvice.AFTER_CORRECTION, "error.mfa_invalid_code", true),
    MFA_CHALLENGE_INVALID("mfa_challenge_invalid", 401, "多因素认证请求无效或已过期", RetryAdvice.AFTER_CORRECTION, "error.mfa_challenge_invalid", true),
    MFA_STATE_CONFLICT("mfa_state_conflict", 409, "多因素认证状态不允许当前操作", RetryAdvice.AFTER_CORRECTION, "error.mfa_state_conflict", true),
    PERMISSION_DENIED("permission_denied", 403, "没有执行该操作的权限", RetryAdvice.NEVER, "error.permission_denied", true),
    DATA_SCOPE_DENIED("data_scope_denied", 403, "没有访问该数据的权限", RetryAdvice.NEVER, "error.data_scope_denied", true),
    SESSION_REVOKED("session_revoked", 401, "会话已撤销或失效", RetryAdvice.NEVER, "error.session_revoked", true),
    ACTIVE_SESSION_CONFLICT("active_session_conflict", 409, "账号已有活动会话", RetryAdvice.AFTER_CORRECTION, "error.active_session_conflict", true),
    RESOURCE_CONFLICT("resource_conflict", 409, "资源状态或唯一约束发生冲突", RetryAdvice.AFTER_CORRECTION, "error.resource_conflict", true),
    API_KEY_NAME_INVALID("api_key_name_invalid", 422, "API Key 名称缺失、空白或超过 128 个字符", RetryAdvice.AFTER_CORRECTION, "error.api_key_name_invalid", true),
    // 仅表示新密码与已验证的当前密码相同，不覆盖密码策略校验失败。
    PASSWORD_SAME_AS_CURRENT("password_same_as_current", 422, "新密码与当前密码相同", RetryAdvice.AFTER_CORRECTION, "error.password_same_as_current", true),
    PASSWORD_REQUIRED("password_required", 422, "密码缺失或为空白", RetryAdvice.AFTER_CORRECTION, "error.password_required", true),
    PASSWORD_TOO_SHORT("password_too_short", 422, "密码长度未达到要求", RetryAdvice.AFTER_CORRECTION, "error.password_too_short", true),
    PASSWORD_DISALLOWED("password_disallowed", 422, "密码位于禁止列表中", RetryAdvice.AFTER_CORRECTION, "error.password_disallowed", true),
    PASSWORD_CONTAINS_USERNAME("password_contains_username", 422, "密码包含用户名", RetryAdvice.AFTER_CORRECTION, "error.password_contains_username", true),
    PASSWORD_MISSING_UPPERCASE("password_missing_uppercase", 422, "密码缺少大写字母", RetryAdvice.AFTER_CORRECTION, "error.password_missing_uppercase", true),
    PASSWORD_MISSING_LOWERCASE("password_missing_lowercase", 422, "密码缺少小写字母", RetryAdvice.AFTER_CORRECTION, "error.password_missing_lowercase", true),
    PASSWORD_MISSING_DIGIT("password_missing_digit", 422, "密码缺少数字", RetryAdvice.AFTER_CORRECTION, "error.password_missing_digit", true),
    PASSWORD_MISSING_SPECIAL("password_missing_special", 422, "密码缺少特殊字符", RetryAdvice.AFTER_CORRECTION, "error.password_missing_special", true),
    // 仅表示个人资料展示名缺失或空白，不复用其他字段校验错误。
    PROFILE_DISPLAY_NAME_REQUIRED("profile_display_name_required", 422, "个人资料展示名缺失或为空白", RetryAdvice.AFTER_CORRECTION, "error.profile_display_name_required", true),
    // 单独更新头像时地址缺失或空白，不能覆盖现有头像。
    PROFILE_AVATAR_REQUIRED("profile_avatar_required", 422, "个人资料头像地址缺失或为空白", RetryAdvice.AFTER_CORRECTION, "error.profile_avatar_required", true),
    API_KEY_EXPIRY_INVALID("api_key_expiry_invalid", 422, "API Key 到期时间格式无法解析", RetryAdvice.AFTER_CORRECTION, "error.api_key_expiry_invalid", true),
    API_KEY_EXPIRY_OUT_OF_RANGE("api_key_expiry_out_of_range", 422, "API Key 到期时间不晚于当前时间或超过 90 天", RetryAdvice.AFTER_CORRECTION, "error.api_key_expiry_out_of_range", true),
    API_KEY_EXPIRED("api_key_expired", 409, "已过期的 API Key 不能轮换", RetryAdvice.AFTER_CORRECTION, "error.api_key_expired", true),
    API_KEY_SCOPE_UNAVAILABLE("api_key_scope_unavailable", 422, "API Key 轮换时原授权范围均不再属于持有人", RetryAdvice.AFTER_CORRECTION, "error.api_key_scope_unavailable", true),
    ROLE_HAS_MEMBERS("role_has_members", 422, "角色仍有关联用户，不能删除", RetryAdvice.AFTER_CORRECTION, "error.role_has_members", true),
    ROLE_PROTECTED("role_protected", 422, "内置管理员角色不能删除", RetryAdvice.NEVER, "error.role_protected", true),
    RATE_LIMITED("rate_limited", 429, "请求频率超过限制", RetryAdvice.AFTER_BACKOFF, "error.rate_limited", true),
    PRECONDITION_REQUIRED("precondition_required", 428, "完成前置条件后才能继续", RetryAdvice.AFTER_CORRECTION, "error.precondition_required", true),
    RESOURCE_NOT_FOUND("resource_not_found", 404, "请求的资源不存在", RetryAdvice.NEVER, "error.resource_not_found", true),
    PAYLOAD_TOO_LARGE("payload_too_large", 413, "请求内容超过允许大小", RetryAdvice.AFTER_CORRECTION, "error.payload_too_large", true),
    HTTPS_REQUIRED("https_required", 426, "请求必须使用 HTTPS", RetryAdvice.AFTER_CORRECTION, "error.https_required", true),
    VALIDATION_FAILED("validation_failed", 422, "请求参数或业务规则校验失败", RetryAdvice.AFTER_CORRECTION, "error.validation_failed", true),
    AUTHORIZATION_UNAVAILABLE("authorization_unavailable", 503, "认证授权状态暂不可用", RetryAdvice.AFTER_BACKOFF, "error.authorization_unavailable", false),
    SERVICE_UNAVAILABLE("service_unavailable", 503, "服务暂不可用", RetryAdvice.AFTER_BACKOFF, "error.service_unavailable", false),
    INTERNAL_ERROR("internal_error", 500, "服务处理失败", RetryAdvice.AFTER_BACKOFF, "error.internal_error", false);

    /** 调用方处理失败后的推荐动作；仅作目录元数据，不改变 HTTP 状态。 */
    public enum RetryAdvice {
        NEVER("never"),
        AFTER_CORRECTION("after_correction"),
        AFTER_BACKOFF("after_backoff");

        private final String key;

        RetryAdvice(String key) {
            this.key = key;
        }

        public String key() {
            return key;
        }
    }

    private static final Map<String, ErrorCode> BY_CODE = Arrays.stream(values())
            .collect(Collectors.toUnmodifiableMap(ErrorCode::code, Function.identity()));

    private final String code;
    private final int httpStatus;
    private final String meaning;
    private final RetryAdvice retryAdvice;
    private final String messageKey;
    private final boolean safeMessage;

    ErrorCode(String code, int httpStatus, String meaning, RetryAdvice retryAdvice, String messageKey, boolean safeMessage) {
        this.code = code;
        this.httpStatus = httpStatus;
        this.meaning = meaning;
        this.retryAdvice = retryAdvice;
        this.messageKey = messageKey;
        this.safeMessage = safeMessage;
    }

    public String code() { return code; }
    public int httpStatus() { return httpStatus; }
    public String meaning() { return meaning; }
    public RetryAdvice retryAdvice() { return retryAdvice; }
    public boolean retryable() { return retryAdvice != RetryAdvice.NEVER; }
    public String messageKey() { return messageKey; }
    public boolean safeMessage() { return safeMessage; }

    /**
     * 按外部错误码查找目录项。
     *
     * <p>未知或空代码返回空结果，调用方可以先区分“未登记”与“已登记”，再决定兼容降级行为。</p>
     */
    public static Optional<ErrorCode> find(String value) {
        if (value == null) return Optional.empty();
        var normalized = value.trim();
        return normalized.isEmpty() ? Optional.empty() : Optional.ofNullable(BY_CODE.get(normalized));
    }

    public static ErrorCode fromCode(String value) {
        return find(value).orElse(VALIDATION_FAILED);
    }

    public static boolean isRegistered(String value) {
        return find(value).isPresent();
    }
}
