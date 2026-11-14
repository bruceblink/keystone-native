package app.keystone.monitor;

import app.keystone.audit.SecurityEventRepository;
import app.keystone.auth.ApiKeyRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;

/** 生成单租户安全运营报告；查询边界和返回字段在这里统一校验。 */
@ApplicationScoped
public class SecurityOperationsReport {
    private static final int DEFAULT_HORIZON_DAYS = 30;
    private static final int MAX_HORIZON_DAYS = 90;
    private static final int DEFAULT_PAGE_SIZE = 20;

    @Inject ApiKeyRepository apiKeys;
    @Inject SecurityEventRepository securityEvents;

    /**
     * 按当前单租户和可选主体筛选生成报告。安全事件只返回脱敏摘要，API Key 只返回生命周期计数。
     */
    public Snapshot generate(String subjectId, String actor, String credentialType, String credentialId,
                             String fromText, String toText, Integer page, Integer size, Integer horizonDays) {
        int days = horizonDays == null ? DEFAULT_HORIZON_DAYS : horizonDays;
        if (days < 1 || days > MAX_HORIZON_DAYS) {
            throw new IllegalArgumentException("horizonDays must be between 1 and 90");
        }
        if (subjectId != null && !subjectId.isBlank()) {
            subjectId = app.keystone.identity.UuidValues.requireCanonical(subjectId);
        } else {
            subjectId = null;
        }
        int safePage = page == null ? 1 : page;
        int safeSize = size == null ? DEFAULT_PAGE_SIZE : size;
        if (safePage < 1 || safeSize < 1 || safeSize > 100) {
            throw new IllegalArgumentException("page must be positive and size must be between 1 and 100");
        }
        Instant now = Instant.now();
        Instant from = parseInstant(fromText, "from");
        Instant to = parseInstant(toText, "to");
        if (from == null) from = now.minus(Duration.ofDays(days));
        if (to == null) to = now;
        if (!from.isBefore(to)) throw new IllegalArgumentException("from must be before to");
        if (Duration.between(from, to).compareTo(Duration.ofDays(MAX_HORIZON_DAYS)) > 0) {
            throw new IllegalArgumentException("report range cannot exceed 90 days");
        }
        return new Snapshot("current", subjectId, from, to,
                apiKeys.rotationReport(subjectId, days),
                securityEvents.report(actor, credentialType, credentialId, from, to, safePage, safeSize));
    }

    private static Instant parseInstant(String value, String field) {
        if (value == null || value.isBlank()) return null;
        try {
            return Instant.parse(value.trim());
        } catch (DateTimeParseException e) {
            throw new IllegalArgumentException(field + " must be an ISO-8601 instant");
        }
    }

    public record Snapshot(String tenantScope, String subjectId, Instant from, Instant to,
                           ApiKeyRepository.RotationReport apiKeys,
                           SecurityEventRepository.ReportPage securityEvents) {
    }
}
