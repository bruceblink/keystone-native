package app.keystone.job;

import java.time.Instant;

public record Job(long id, String code, String name, String cron, boolean enabled, String lastStatus, Instant lastRunAt) {}
