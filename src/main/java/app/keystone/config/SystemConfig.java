package app.keystone.config;

import java.time.Instant;

public record SystemConfig(long id, String key, String value, String description, boolean enabled, Instant updatedAt) {}
