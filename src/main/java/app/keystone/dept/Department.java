package app.keystone.dept;

public record Department(String id, String parentId, String code, String name, int sortOrder, boolean enabled) {}
