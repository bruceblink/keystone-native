package app.keystone;

import app.keystone.auth.ApiKeyRoleEntity;
import app.keystone.auth.ApiKeyUserEntity;
import app.keystone.config.SystemConfigEntity;
import app.keystone.dept.DepartmentEntity;
import app.keystone.dict.DictionaryItemEntity;
import app.keystone.dict.DictionaryTypeEntity;
import app.keystone.menu.MenuEntity;
import app.keystone.menu.MenuRepository;
import app.keystone.notice.NoticeEntity;
import app.keystone.post.PostEntity;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;

import static org.junit.jupiter.api.Assertions.assertFalse;

/** 验证各管理资源的新建领域对象保留显式停用状态。 */
class EnabledCreateStateTest {
    @Test
    void explicitFalseDisablesEveryManagedEntity() throws Exception {
        assertDisabled(DepartmentEntity.class, new Class<?>[]{String.class, String.class, String.class, int.class, Boolean.class},
                "dept", "部门", null, 0, false);
        assertDisabled(PostEntity.class, new Class<?>[]{String.class, String.class, int.class, Boolean.class},
                "post", "岗位", 0, false);
        assertDisabled(ApiKeyRoleEntity.class, new Class<?>[]{String.class, String.class, Boolean.class},
                "ROLE", "角色", false);
        assertDisabled(DictionaryTypeEntity.class, new Class<?>[]{String.class, String.class, Boolean.class},
                "TYPE", "类型", false);
        var type = newEntity(DictionaryTypeEntity.class, new Class<?>[]{String.class, String.class, Boolean.class}, "TYPE2", "类型", true);
        assertDisabled(DictionaryItemEntity.class, new Class<?>[]{DictionaryTypeEntity.class, String.class, String.class, int.class, Boolean.class},
                type, "item", "条目", 0, false);
        assertDisabled(SystemConfigEntity.class, new Class<?>[]{String.class, String.class, String.class, Boolean.class},
                "config", "value", null, false);
        assertDisabled(NoticeEntity.class, new Class<?>[]{String.class, String.class, String.class, String.class, String.class, Boolean.class},
                "标题", "内容", "NOTICE", "admin", null, false);
        assertDisabled(MenuEntity.class, new Class<?>[]{MenuRepository.MenuRequest.class},
                new MenuRepository.MenuRequest(null, "menu", "菜单", null, null, "MENU", null, 0, false));
        assertDisabled(ApiKeyUserEntity.class, new Class<?>[]{String.class, String.class, String.class, String.class, String.class,
                        String.class, String.class, Integer.class, String.class, String.class, Boolean.class},
                "user", "hash", "用户", null, null, null, null, null, null, null, false);
    }

    private static void assertDisabled(Class<?> type, Class<?>[] parameterTypes, Object... arguments) throws Exception {
        Object entity = newEntity(type, parameterTypes, arguments);
        Field enabled = type.getDeclaredField("enabled");
        enabled.setAccessible(true);
        assertFalse(enabled.getBoolean(entity), type.getSimpleName());
    }

    private static <T> T newEntity(Class<T> type, Class<?>[] parameterTypes, Object... arguments) throws Exception {
        Constructor<T> constructor = type.getDeclaredConstructor(parameterTypes);
        constructor.setAccessible(true);
        return constructor.newInstance(arguments);
    }
}
