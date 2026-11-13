package app.keystone.job;

import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 验证计划任务和执行记录使用 ORM，不重新引入 JDBC。 */
class JobOrmPersistenceTest {
    @Test
    void repositoriesUsePanacheWithoutManualJdbc() throws Exception {
        String jobs = Files.readString(Path.of("src/main/java/app/keystone/job/JobRepository.java"));
        String logs = Files.readString(Path.of("src/main/java/app/keystone/job/JobLogRepository.java"));
        assertTrue(jobs.contains("PanacheRepository<JobEntity>"));
        assertTrue(logs.contains("PanacheRepository<JobLogEntity>"));
        assertTrue(jobs.contains("@Transactional"));
        assertTrue(logs.contains("@Transactional"));
        assertFalse(jobs.contains("DataSource"));
        assertFalse(logs.contains("DataSource"));
        assertFalse(jobs.contains("prepareStatement"));
        assertFalse(logs.contains("prepareStatement"));
    }

    @Test
    void entitiesMapSchedulerColumns() throws Exception {
        String job = Files.readString(Path.of("src/main/java/app/keystone/job/JobEntity.java"));
        String log = Files.readString(Path.of("src/main/java/app/keystone/job/JobLogEntity.java"));
        assertTrue(job.contains("invoke_target"));
        assertTrue(job.contains("last_run_at"));
        assertTrue(log.contains("job_id"));
        assertTrue(log.contains("started_at"));
        assertTrue(log.contains("finished_at"));
        assertTrue(log.contains("duration_ms"));
    }
}
