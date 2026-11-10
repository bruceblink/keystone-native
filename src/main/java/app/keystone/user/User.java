package app.keystone.user;

import java.util.List;

public record User(long id, String username, String displayName, Long deptId, boolean enabled, List<String> roles) {}
