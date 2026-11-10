package app.keystone.job;

import io.quarkus.scheduler.ScheduledExecution;
import io.quarkus.scheduler.Scheduler;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

@ApplicationScoped
public class JobService {
    private static final Logger LOG = Logger.getLogger(JobService.class);
    @Inject Scheduler scheduler;
    @Inject JobRepository jobs;

    void onStart(@Observes StartupEvent ignored) {
        for (Job job : jobs.enabled()) schedule(job);
    }

    public Job create(String code, String name, String cron) {
        validateCron(cron);
        Job job = jobs.create(code, name, cron);
        schedule(job);
        return job;
    }

    public java.util.List<Job> jobs() { return jobs.list(); }

    public Job update(long id, String name, String cron, Boolean enabled) {
        if (cron != null && !cron.isBlank()) validateCron(cron);
        unschedule(id);
        Job job = jobs.update(id, name, cron, enabled);
        if (job.enabled()) schedule(job);
        return job;
    }

    public void delete(long id) { unschedule(id); jobs.delete(id); }

    public void trigger(long id) { run(id, null); }

    private void schedule(Job job) {
        String schedulerId = schedulerId(job.id());
        if (scheduler.getScheduledJob(schedulerId) != null) scheduler.unscheduleJob(schedulerId);
        scheduler.newJob(schedulerId).setCron(job.cron()).setDescription(job.name()).setTask((ScheduledExecution execution) -> run(job.id(), execution)).schedule();
    }

    private void unschedule(long id) { if (scheduler.getScheduledJob(schedulerId(id)) != null) scheduler.unscheduleJob(schedulerId(id)); }
    private void run(long id, ScheduledExecution execution) { try { LOG.infof("Executing Keystone job %d%s", id, execution == null ? " manually" : ""); jobs.markRun(id, "SUCCESS"); } catch (Exception e) { LOG.errorf(e, "Keystone job %d failed", id); jobs.markRun(id, "FAILED"); } }
    private static String schedulerId(long id) { return "keystone-job-" + id; }
    private static void validateCron(String cron) { if (cron == null || cron.isBlank()) throw new IllegalArgumentException("cron is required"); try { new io.quarkus.scheduler.common.runtime.CronParser(com.cronutils.model.CronType.QUARTZ).parse(cron); } catch (Exception e) { throw new IllegalArgumentException("invalid cron expression", e); } }
}
