package app.keystone.menu;

public record Menu(long id, Long parentId, String code, String name, String path, String component,
                   String menuType, String permission, int sortOrder, boolean enabled) {}
