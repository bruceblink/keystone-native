package app.keystone.audit;

import java.time.Instant;

public record OperationLog(String id, String actorUsername, String action, String resource, String resourceId, String detail, Instant createdAt) {}
