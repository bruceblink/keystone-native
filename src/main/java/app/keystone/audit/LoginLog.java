package app.keystone.audit;

import java.time.Instant;

public record LoginLog(String id, String username, String status, String ipAddress, String message,
                       String userAgent, Instant loginAt) {}
