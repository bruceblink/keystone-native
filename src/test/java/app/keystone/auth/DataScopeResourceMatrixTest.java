package app.keystone.auth;

import app.keystone.audit.OperationLogResource;
import app.keystone.config.SystemConfigResource;
import app.keystone.dict.DictionaryResource;
import app.keystone.file.FileResource;
import app.keystone.job.JobResource;
import app.keystone.menu.MenuResource;
import app.keystone.monitor.MonitorResource;
import app.keystone.monitor.SecurityObservabilityResource;
import app.keystone.post.PostResource;
import app.keystone.profile.ProfileResource;
import app.keystone.role.RoleResource;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** 检查需要全局范围或明确 owner 关系的资源都声明了统一矩阵入口。 */
class DataScopeResourceMatrixTest {
    @Test
    void protectedResourcesDeclareTheirMatrixResource() {
        Map<Class<?>, String> expected = Map.ofEntries(
                Map.entry(RoleResource.class, "role"),
                Map.entry(PostResource.class, "post"),
                Map.entry(MenuResource.class, "menu"),
                Map.entry(SystemConfigResource.class, "config"),
                Map.entry(DictionaryResource.class, "dictionary"),
                Map.entry(JobResource.class, "job"),
                Map.entry(OperationLogResource.class, "audit"),
                Map.entry(MonitorResource.class, "session"),
                Map.entry(SecurityObservabilityResource.class, "audit"),
                Map.entry(FileResource.class, "file"),
                Map.entry(ProfileResource.class, "profile"));

        expected.forEach((resource, value) -> assertEquals(
                value, resource.getAnnotation(RequiresDataScope.class).value(), resource.getName()));
    }
}
