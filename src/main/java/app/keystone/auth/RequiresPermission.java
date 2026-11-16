package app.keystone.auth;

import jakarta.interceptor.InterceptorBinding;
import jakarta.enterprise.util.Nonbinding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 声明资源方法需要的稳定权限码。 */
@InterceptorBinding
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface RequiresPermission {
    @Nonbinding
    String value() default "";

    /** 同一入口允许多个等价权限时使用；非空后忽略 value。 */
    @Nonbinding
    String[] any() default {};
}
