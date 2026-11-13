package app.keystone.job;

import java.time.Instant;

public record Job(String id, String code, String name, String group, String invokeTarget, String jobParams,
                  String cron, boolean concurrent, boolean enabled, String remark,
                  String lastStatus, Instant lastRunAt) {}
