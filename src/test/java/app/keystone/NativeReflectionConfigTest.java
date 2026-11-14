package app.keystone;

import app.keystone.user.UserResource;
import io.quarkus.runtime.annotations.RegisterForReflection;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** 确认 Native JSON 响应使用的导入结果记录已进入反射配置。 */
class NativeReflectionConfigTest {
    @Test
    void registersUserImportResponseRecords() {
        RegisterForReflection registration = NativeReflectionConfig.class.getAnnotation(RegisterForReflection.class);
        Set<Class<?>> targets = Set.copyOf(Arrays.asList(registration.targets()));

        assertTrue(targets.contains(UserResource.ImportResult.class));
        assertTrue(targets.contains(UserResource.ImportFailure.class));
    }
}
