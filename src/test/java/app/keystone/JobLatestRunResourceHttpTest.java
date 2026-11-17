package app.keystone;

import app.keystone.job.JobLog;
import app.keystone.job.JobLogRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 用真实 MySQL 和 HTTP 检查任务执行日志与最近状态的一致性。 */
@QuarkusTest
class JobLatestRunResourceHttpTest extends AuthTestFixture {
    @Inject JobLogRepository jobLogs;

    /** 手动运行成功后，任务接口和日志接口必须返回相同的完成时间。 */
    @Test
    void successfulHttpRunPersistsMatchingLatestStateAndLog() throws Exception {
        String token = login();
        String code = jobCode("success");
        String id = createJob(token, code);
        try {
            trigger(token, id).then().statusCode(200).body("data.triggered", is(true));

            Map<?, ?> job = getJob(token, id);
            assertEquals("SUCCESS", job.get("lastStatus"));
            String lastRunAt = (String) job.get("lastRunAt");
            assertNotNull(lastRunAt);
            assertTrue(Instant.parse(lastRunAt).isAfter(Instant.now().minusSeconds(60)));

            Map<?, ?> log = getLogs(token, id).get(0);
            assertEquals(1, ((Number) log.get("status")).intValue());
            assertEquals(lastRunAt, log.get("finishedAt"));
        } finally {
            deleteLogs(id);
            deleteJob(token, id);
        }
    }

    /** MySQL 拒绝写日志时，HTTP 失败响应不得留下没有日志的最近状态。 */
    @Test
    void failedLogInsertRollsBackLatestState() throws Exception {
        String token = login();
        String code = jobCode("reject");
        String id = createJob(token, code);
        String constraint = "reject_job_log_" + UUID.randomUUID().toString().replace("-", "");
        boolean constraintCreated = false;
        try {
            try (var connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
                statement.execute("ALTER TABLE sys_job_log ADD CONSTRAINT " + constraint
                        + " CHECK (job_code <> '" + code + "')");
                constraintCreated = true;
            }

            trigger(token, id).then().statusCode(503);
            given().auth().oauth2(token).when().get("/v1/jobs/" + id).then().statusCode(200)
                    .body("data.lastStatus", nullValue()).body("data.lastRunAt", nullValue());
            given().auth().oauth2(token).when().get("/v1/jobs/logs?jobId=" + id).then()
                    .statusCode(200).body("data.total", is(0));
        } finally {
            if (constraintCreated) {
                try (var connection = dataSource.getConnection(); Statement statement = connection.createStatement()) {
                    statement.execute("ALTER TABLE sys_job_log DROP CHECK " + constraint);
                }
            }
            deleteJob(token, id);
        }
    }

    /** 相同秒内按微秒时间保存结果，并检查跳过、成功和较旧失败状态。 */
    @Test
    void olderSameSecondResultCannotReplaceNewerResult() throws Exception {
        String token = login();
        String code = jobCode("precision");
        String id = createJob(token, code);
        Instant base = Instant.now().plusSeconds(2).truncatedTo(ChronoUnit.SECONDS);
        Instant older = base.plusMillis(100);
        Instant skippedAt = base.plusMillis(200);
        Instant newer = base.plusMillis(400);
        try {
            jobLogs.save(runLog(id, code, 2, skippedAt));
            assertEquals("SKIPPED", getJob(token, id).get("lastStatus"));
            jobLogs.save(runLog(id, code, 1, newer));
            jobLogs.save(runLog(id, code, 0, older));
            Map<?, ?> job = getJob(token, id);
            assertEquals("SUCCESS", job.get("lastStatus"));
            assertEquals(newer, Instant.parse((String) job.get("lastRunAt")));
            var logs = getLogs(token, id);
            assertEquals(3, logs.size());
            Set<Integer> statuses = logs.stream()
                    .map(log -> ((Number) log.get("status")).intValue())
                    .collect(java.util.stream.Collectors.toSet());
            assertEquals(Set.of(0, 1, 2), statuses);
        } finally {
            deleteLogs(id);
            deleteJob(token, id);
        }
    }

    private String createJob(String token, String code) {
        return given().auth().oauth2(token).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"Latest run HTTP test\","
                        + "\"group\":\"TEST\",\"cron\":\"0/30 * * * * ?\","
                        + "\"invokeTarget\":\"keystoneJob.heartbeat()\",\"concurrent\":true,\"enabled\":false}")
                .when().post("/v1/jobs").then().statusCode(201).extract().path("data.id");
    }

    private Map<?, ?> getJob(String token, String id) {
        return (Map<?, ?>) given().auth().oauth2(token).when().get("/v1/jobs/" + id).then()
                .statusCode(200).extract().path("data");
    }

    private java.util.List<Map<?, ?>> getLogs(String token, String id) {
        return given().auth().oauth2(token).when().get("/v1/jobs/logs?jobId=" + id).then()
                .statusCode(200).extract().jsonPath().getList("data.items");
    }

    private Response trigger(String token, String id) {
        return given().auth().oauth2(token).when().post("/v1/jobs/" + id + "/trigger");
    }

    private void deleteJob(String token, String id) {
        if (id != null) given().auth().oauth2(token).when().delete("/v1/jobs/" + id).then().statusCode(200);
    }

    private void deleteLogs(String id) throws Exception {
        try (var connection = dataSource.getConnection();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM sys_job_log WHERE job_id = UUID_TO_BIN(?, 0)")) {
            statement.setString(1, id);
            statement.executeUpdate();
        }
    }

    private static JobLog runLog(String id, String code, int status, Instant finishedAt) {
        return new JobLog(null, id, code, "Latest run HTTP test", "TEST", "keystoneJob.heartbeat()", null,
                "0/30 * * * * ?", 2, status, "integration result", null, finishedAt.minusSeconds(1),
                finishedAt, 1000L, finishedAt);
    }

    private static String jobCode(String suffix) {
        return "latest-" + suffix + "-" + UUID.randomUUID().toString().replace("-", "");
    }

    private String login() {
        return given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
