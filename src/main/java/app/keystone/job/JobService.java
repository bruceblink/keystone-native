package app.keystone.job;

import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationDeniedException;
import app.keystone.auth.AuthorizationService;
import io.quarkus.scheduler.ScheduledExecution;
import io.quarkus.scheduler.Scheduler;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

@ApplicationScoped
public class JobService {
    private static final Logger LOG = Logger.getLogger(JobService.class);
    private static final AuthorizationContext SCHEDULER_CONTEXT = AuthorizationContext.system();
    private static final int AUTO_TRIGGER = 1;
    private static final int MANUAL_TRIGGER = 2;
    private static final int SUCCESS = 1;
    private static final int FAILED = 0;
    private static final int SKIPPED = 2;

    @Inject Scheduler scheduler;
    @Inject JobRepository jobs;
    @Inject JobInvocationService invocations;
    @Inject JobLogRepository jobLogs;
    @Inject AuthorizationService authorization;
    private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();

    void onStart(@Observes StartupEvent ignored) {
        for (Job job : jobs.enabled(SCHEDULER_CONTEXT)) schedule(job);
    }

    public Job create(AuthorizationContext context, String code, String name, String group, String invokeTarget, String jobParams, String cron, Boolean concurrent, Boolean enabled, String remark) {
        authorization.require(context, "job:create", "job");
        validateCron(cron);
        String target = invokeTarget == null || invokeTarget.isBlank() ? "keystoneJob.heartbeat()" : invokeTarget;
        invocations.validate(target, jobParams);
        Job job = jobs.create(context, code, name, group, target, jobParams, cron, concurrent, enabled, remark);
        schedule(job);
        return job;
    }

    public List<Job> jobs(AuthorizationContext context) {
        authorization.require(context, "job:read", "job");
        return jobs.list(context);
    }

    public Job update(AuthorizationContext context, String id, String name, String group, String invokeTarget, String jobParams, String cron, Boolean concurrent, Boolean enabled, String remark) {
        authorization.require(context, "job:update", "job");
        Job current = jobs.findById(context, id, "job:update");
        if (cron != null && !cron.isBlank()) validateCron(cron);
        String target = invokeTarget == null || invokeTarget.isBlank() ? current.invokeTarget() : invokeTarget;
        String params = jobParams == null ? current.jobParams() : jobParams;
        invocations.validate(target, params);
        unschedule(id);
        Job job;
        try { job = jobs.update(context, id, name, group, invokeTarget, jobParams, cron, concurrent, enabled, remark); }
        catch (RuntimeException e) { if (current.enabled()) schedule(current); throw e; }
        if (job.enabled()) schedule(job);
        return job;
    }

    public void delete(AuthorizationContext context, String id) {
        authorization.require(context, "job:delete", "job");
        jobs.findById(context, id, "job:delete");
        unschedule(id);
        jobs.delete(context, id);
        locks.remove(id);
    }

    /** 先停用全部调度，再以单事务删除任务；数据库失败时恢复原有调度。 */
    public int deleteAll(AuthorizationContext context, List<String> ids) {
        authorization.require(context, "job:delete", "job");
        List<Job> targets = jobs.findAll(context, ids, "job:delete");
        targets.forEach(job -> unschedule(job.id()));
        try {
            List<Job> deleted = jobs.deleteAll(context, ids);
            deleted.forEach(job -> locks.remove(job.id()));
            return deleted.size();
        } catch (RuntimeException failure) {
            targets.stream().filter(Job::enabled).forEach(this::schedule);
            throw failure;
        }
    }

    public void trigger(AuthorizationContext context, String id) {
        authorization.require(context, "job:run", "job");
        run(jobs.findById(context, id, "job:run"), MANUAL_TRIGGER);
    }

    public List<JobInvocationService.JobTarget> targets(AuthorizationContext context) {
        authorization.require(context, "job:read", "job");
        return invocations.targets();
    }

    public JobLogRepository.Page logs(AuthorizationContext context, String jobId, int page, int size) {
        authorization.require(context, "job:read", "job");
        if (jobId == null || jobId.isBlank()) {
            return context.allScope() ? jobLogs.list(null, page, size) : jobLogs.listForOwner(context.subjectId(), page, size);
        }
        try {
            jobs.findById(context, jobId);
        } catch (java.util.NoSuchElementException e) {
            throw new AuthorizationDeniedException("data_scope_denied", 403,
                    "data scope does not allow this resource");
        }
        return jobLogs.list(jobId, page, size);
    }

    private void schedule(Job job) {
        String schedulerId = schedulerId(job.id());
        if (scheduler.getScheduledJob(schedulerId) != null) scheduler.unscheduleJob(schedulerId);
        scheduler.newJob(schedulerId).setCron(job.cron()).setDescription(job.name()).setTask((ScheduledExecution execution) -> run(job.id(), execution)).schedule();
    }

    private void unschedule(String id) {
        String idValue = schedulerId(id);
        if (scheduler.getScheduledJob(idValue) != null) scheduler.unscheduleJob(idValue);
    }

    private void run(String id, ScheduledExecution execution) {
        try { run(jobs.findById(SCHEDULER_CONTEXT, id, "job:run"), AUTO_TRIGGER); }
        catch (Exception e) { LOG.errorf(e, "Keystone job %s failed", id); }
    }

    private void run(Job job, int triggerType) {
        Instant started = Instant.now();
        long startNanos = System.nanoTime();
        int status = SUCCESS;
        String message = "任务执行成功";
        String exception = null;
        RuntimeException failure = null;
        ReentrantLock lock = locks.computeIfAbsent(job.id(), ignored -> new ReentrantLock());
        boolean locked = job.concurrent() || lock.tryLock();
        if (!locked) {
            status = SKIPPED;
            message = "任务正在执行，本次触发已跳过";
        } else {
            try {
                LOG.infof("Executing Keystone job %s (%s)", job.id(), job.invokeTarget());
                invocations.invoke(job.invokeTarget(), job.jobParams());
                jobs.markRun(job.id(), "SUCCESS");
            } catch (Exception e) {
                status = FAILED;
                message = "任务执行失败: " + trim(e.getMessage(), 450);
                exception = trim(stackTrace(e), 4000);
                failure = e instanceof RuntimeException runtime ? runtime : new IllegalStateException(e);
                jobs.markRun(job.id(), "FAILED");
                if (triggerType == AUTO_TRIGGER) LOG.errorf(e, "Keystone job %s failed", job.id());
            } finally {
                if (!job.concurrent()) lock.unlock();
            }
        }
        if (status == SKIPPED) jobs.markRun(job.id(), "SKIPPED");
        Instant finished = Instant.now();
        jobLogs.save(new JobLog(null, job.id(), job.code(), job.name(), job.group(), job.invokeTarget(), job.jobParams(), job.cron(), triggerType, status, message, exception, started, finished, (System.nanoTime() - startNanos) / 1_000_000, finished));
        if (failure != null && triggerType == MANUAL_TRIGGER) throw failure;
    }

    private static String schedulerId(String id) { return "keystone-job-" + id; }
    private static String trim(String value, int max) { if (value == null) return ""; return value.length() <= max ? value : value.substring(0, max); }
    private static String stackTrace(Exception e) { var out = new java.io.StringWriter(); e.printStackTrace(new java.io.PrintWriter(out)); return out.toString(); }
    private static void validateCron(String cron) {
        if (cron == null || cron.isBlank()) throw new IllegalArgumentException("cron is required");
        try { new io.quarkus.scheduler.common.runtime.CronParser(com.cronutils.model.CronType.QUARTZ).parse(cron); }
        catch (Exception e) { throw new IllegalArgumentException("invalid cron expression", e); }
    }
}
