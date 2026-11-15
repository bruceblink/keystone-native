package app.keystone.menu;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** 验证菜单实体会保存父级重排结果，支持移动到根节点。 */
class MenuEntityTest {
    @Test
    void updateStoresNewParentAndCanMoveToRoot() {
        String initialParent = UUID.randomUUID().toString();
        String replacementParent = UUID.randomUUID().toString();
        var entity = new MenuEntity(new MenuRepository.MenuRequest(
                initialParent, "menu", "菜单", null, null, "MENU", null, 0, true));

        entity.update(new MenuRepository.MenuRequest(
                replacementParent, null, "更新菜单", null, null, null, null, null, null),
                UUID.fromString(replacementParent));
        assertEquals(replacementParent, entity.toModel().parentId());

        entity.update(new MenuRepository.MenuRequest(
                null, null, "根菜单", null, null, null, null, null, null), null);
        assertNull(entity.toModel().parentId());
    }
}
