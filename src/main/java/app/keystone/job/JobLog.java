package app.keystone.job;

import java.time.Instant;

public record JobLog(Long id, Long jobId, String jobCode, String jobName, String jobGroup,
                     String invokeTarget, String jobParams, String cron, int triggerType,
                     int status, String jobMessage, String exceptionInfo, Instant startedAt,
                     Instant finishedAt, Long durationMs, Instant createdAt) {}
