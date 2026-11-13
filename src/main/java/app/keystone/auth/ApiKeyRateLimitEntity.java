package app.keystone.auth;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** 映射 API Key 失败限流记录；数据库结构仍由 Flyway 管理。 */
@Entity
@Table(name = "sys_api_key_rate_limit")
public class ApiKeyRateLimitEntity {
    @Id
    @Column(name = "scope_key", nullable = false, length = 64)
    private String scopeKey;

    @Column(name = "window_started_at", nullable = false)
    private Instant windowStartedAt;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "blocked_until")
    private Instant blockedUntil;

    protected ApiKeyRateLimitEntity() {
    }

    ApiKeyRateLimitEntity(String scopeKey, Instant windowStartedAt, int attemptCount, Instant blockedUntil) {
        this.scopeKey = scopeKey;
        this.windowStartedAt = windowStartedAt;
        this.attemptCount = attemptCount;
        this.blockedUntil = blockedUntil;
    }

    String scopeKey() {
        return scopeKey;
    }

    Instant windowStartedAt() {
        return windowStartedAt;
    }

    int attemptCount() {
        return attemptCount;
    }

    void update(Instant windowStartedAt, int attemptCount, Instant blockedUntil) {
        this.windowStartedAt = windowStartedAt;
        this.attemptCount = attemptCount;
        this.blockedUntil = blockedUntil;
    }

    boolean isBlockedAt(Instant now) {
        return blockedUntil != null && blockedUntil.isAfter(now);
    }
}
