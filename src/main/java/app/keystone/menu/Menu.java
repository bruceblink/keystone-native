package app.keystone.menu;

public record Menu(String id, String parentId, String code, String name, String path, String component,
                   String menuType, String permission, int sortOrder, boolean enabled) {}
