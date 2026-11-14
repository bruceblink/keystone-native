package app.keystone.audit;

import java.time.Duration;
import java.time.Instant;

/** 定义安全事件的保留时间、总量上限和单次清理批量。 */
public record SecurityEventRetentionPolicy(int retentionDays, long maxEvents, int cleanupBatchSize) {
    public SecurityEventRetentionPolicy {
        if (retentionDays < 1 || retentionDays > 3650) throw new IllegalArgumentException("security event retention days must be between 1 and 3650");
        if (maxEvents < 100 || maxEvents > 100_000_000) throw new IllegalArgumentException("security event max events must be between 100 and 100000000");
        if (cleanupBatchSize < 1 || cleanupBatchSize > 10_000) throw new IllegalArgumentException("security event cleanup batch size must be between 1 and 10000");
    }

    /** 计算清理截止时间；边界时间之前的事件可以被删除。 */
    public Instant cutoff(Instant now) {
        if (now == null) throw new IllegalArgumentException("cleanup time is required");
        return now.minus(Duration.ofDays(retentionDays));
    }
}
