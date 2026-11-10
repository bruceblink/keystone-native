package app.keystone.user;

import java.util.List;

public record User(long id, String username, String displayName, boolean enabled, List<String> roles) {}
