package app.keystone.job;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import javax.sql.DataSource;
import java.sql.ResultSet;
import java.util.ArrayList;

@ApplicationScoped
public class JobLogRepository {
    @Inject DataSource dataSource;

    public void save(JobLog log) {
        String sql = "INSERT INTO sys_job_log(job_id, job_code, job_name, job_group, invoke_target, job_params, cron, trigger_type, status, job_message, exception_info, started_at, finished_at, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(sql)) {
            if (log.jobId() == null) p.setNull(1, java.sql.Types.BIGINT); else p.setLong(1, log.jobId());
            p.setString(2, log.jobCode()); p.setString(3, log.jobName()); p.setString(4, log.jobGroup());
            p.setString(5, log.invokeTarget()); p.setString(6, log.jobParams()); p.setString(7, log.cron());
            p.setInt(8, log.triggerType()); p.setInt(9, log.status()); p.setString(10, log.jobMessage()); p.setString(11, log.exceptionInfo());
            p.setTimestamp(12, java.sql.Timestamp.from(log.startedAt()));
            if (log.finishedAt() == null) p.setNull(13, java.sql.Types.TIMESTAMP); else p.setTimestamp(13, java.sql.Timestamp.from(log.finishedAt()));
            if (log.durationMs() == null) p.setNull(14, java.sql.Types.BIGINT); else p.setLong(14, log.durationMs());
            p.executeUpdate();
        } catch (Exception e) { throw new IllegalStateException("Could not save job log", e); }
    }

    public Page list(Long jobId, int page, int size) {
        int safePage = Math.max(1, page), safeSize = Math.min(100, Math.max(1, size)), offset = (safePage - 1) * safeSize;
        String filter = jobId == null ? "" : " WHERE job_id = ?";
        try (var c = dataSource.getConnection();
             var count = c.prepareStatement("SELECT COUNT(*) FROM sys_job_log" + filter);
             var p = c.prepareStatement("SELECT id, job_id, job_code, job_name, job_group, invoke_target, job_params, cron, trigger_type, status, job_message, exception_info, started_at, finished_at, duration_ms, created_at FROM sys_job_log" + filter + " ORDER BY id DESC LIMIT ? OFFSET ?")) {
            if (jobId != null) { count.setLong(1, jobId); p.setLong(1, jobId); }
            long total;
            try (var rs = count.executeQuery()) { rs.next(); total = rs.getLong(1); }
            int index = jobId == null ? 1 : 2; p.setInt(index, safeSize); p.setInt(index + 1, offset);
            var items = new ArrayList<JobLog>();
            try (var rs = p.executeQuery()) { while (rs.next()) items.add(read(rs)); }
            return new Page(items, safePage, safeSize, total);
        } catch (Exception e) { throw new IllegalStateException("Could not list job logs", e); }
    }

    private static JobLog read(ResultSet rs) throws Exception {
        var started = rs.getTimestamp("started_at"); var finished = rs.getTimestamp("finished_at"); var created = rs.getTimestamp("created_at");
        long jobId = rs.getLong("job_id");
        return new JobLog(rs.getLong("id"), rs.wasNull() ? null : jobId, rs.getString("job_code"), rs.getString("job_name"), rs.getString("job_group"), rs.getString("invoke_target"), rs.getString("job_params"), rs.getString("cron"), rs.getInt("trigger_type"), rs.getInt("status"), rs.getString("job_message"), rs.getString("exception_info"), started == null ? null : started.toInstant(), finished == null ? null : finished.toInstant(), rs.getObject("duration_ms", Long.class), created == null ? null : created.toInstant());
    }

    public record Page(java.util.List<JobLog> items, int page, int size, long total) {}
}
