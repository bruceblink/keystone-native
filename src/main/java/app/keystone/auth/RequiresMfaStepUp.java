package app.keystone.auth;

import jakarta.interceptor.InterceptorBinding;
import jakarta.enterprise.util.Nonbinding;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 声明敏感操作需要当前会话在最近十分钟内完成 MFA 二次验证。 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface RequiresMfaStepUp {
    /** 强制要求当前访问令牌具有 AAL2，即使用户没有启用强制 MFA 策略。 */
    @Nonbinding
    boolean enforce() default false;
}
