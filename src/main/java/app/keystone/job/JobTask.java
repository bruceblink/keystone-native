package app.keystone.job;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** Marks a CDI method as safe for database-backed scheduled-job invocation. */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface JobTask {
    String name() default "";
    String group() default "default";
    String description() default "";
}
