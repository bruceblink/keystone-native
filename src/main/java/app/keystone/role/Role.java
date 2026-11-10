package app.keystone.role;

import java.util.List;

public record Role(long id, String code, String name, boolean enabled, String dataScope, String deptScope, List<String> permissions) {}
