package app.keystone.dept;

public record Department(long id, Long parentId, String code, String name, int sortOrder, boolean enabled) {}
