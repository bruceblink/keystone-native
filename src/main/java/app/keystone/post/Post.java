package app.keystone.post;

public record Post(long id, String code, String name, int sortOrder, boolean enabled) {}
