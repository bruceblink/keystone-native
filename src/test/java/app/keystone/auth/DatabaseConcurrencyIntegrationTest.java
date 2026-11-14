package app.keystone.auth;

import app.keystone.identity.UuidValues;
import app.keystone.user.UserRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.elytron.security.common.BcryptUtil;
import jakarta.inject.Inject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 使用真实 MySQL 事务验证刷新令牌、API Key 和 MFA 一次性凭据的单成功规则。 */
@QuarkusTest
class DatabaseConcurrencyIntegrationTest {
    @Inject ApiKeyUserRepository users;
    @Inject SessionRepository sessions;
    @Inject ApiKeyRepository keys;
    @Inject MfaRepository mfa;
    @Inject MfaRecoveryCodeService recoveryCodes;

    private String adminId;
    private String mfaUserId;
    private final List<String> apiKeyIds = new ArrayList<>();

    @AfterEach
    void cleanSessionsAndKeys() {
        if (adminId != null) {
            for (String id : apiKeyIds) {
                try {
                    keys.revoke(adminId, id);
                } catch (RuntimeException ignored) {
                    // 并发轮换可能已经撤销旧 key；清理不能掩盖主断言结果。
                }
            }
            sessions.revokeAll(adminId);
        }
        if (mfaUserId != null) {
            users.deleteUser(mfaUserId, DataScopeService.Scope.unrestricted(), null);
            mfaUserId = null;
        }
    }

    @Test
    void oneRefreshRotationWinsWhenTwoMySqlTransactionsStartTogether() throws Exception {
        UserRepository.AuthUser admin = admin();
        SessionRepository.CreatedSession created = sessions.create(admin.id(), true, "web").orElseThrow();

        List<Optional<SessionRepository.RotatedSession>> results = runTogether(() ->
                sessions.rotate(created.refreshToken(), null, "web"));

        assertEquals(1, results.stream().filter(Optional::isPresent).count());
        assertEquals(1, results.stream().filter(Optional::isEmpty).count());
        SessionRepository.RotatedSession winner = results.stream()
                .flatMap(Optional::stream)
                .findFirst()
                .orElseThrow();
        assertNotNull(winner.refreshToken());
        // 旧令牌重用会撤销整个令牌族，确保第二个事务没有留下可用会话。
        assertTrue(!sessions.isAccessTokenActive(winner.accessTokenId()));
    }

    @Test
    void oneApiKeyRotationWinsWhenTwoMySqlTransactionsStartTogether() throws Exception {
        UserRepository.AuthUser admin = admin();
        ApiKeyRepository.IssuedApiKey issued = keys.issue(admin.id(), "concurrency-test",
                List.of("audit:read"), null);
        apiKeyIds.add(issued.id());

        List<Object> results = runTogether(() -> {
            try {
                ApiKeyRepository.IssuedApiKey replacement = keys.rotate(admin.id(), issued.id());
                apiKeyIds.add(replacement.id());
                return replacement;
            } catch (RuntimeException error) {
                return error;
            }
        });

        assertEquals(1, results.stream().filter(ApiKeyRepository.IssuedApiKey.class::isInstance).count());
        assertEquals(1, results.stream().filter(IllegalArgumentException.class::isInstance).count());
    }

    @Test
    void oneMfaRecoveryCodeConsumptionWinsWhenTwoMySqlTransactionsStartTogether() throws Exception {
        var testUser = users.createUser("concurrency-mfa-" + UuidValues.v7().substring(0, 8),
                BcryptUtil.bcryptHash("Concurrency-Mfa-Password-1"), "Concurrency MFA", null, null,
                null, null, null, null, null, List.of("USER"));
        mfaUserId = testUser.id();
        String code = "0123-4567-89AB-CDEF-0123-4567-89AB-CDEF";
        String hash = recoveryCodes.hash(code);
        mfa.replaceRecoveryCodes(mfaUserId, UuidValues.v7(), List.of(hash));

        List<Boolean> results = runTogether(() -> mfa.consumeRecoveryCode(mfaUserId, hash));

        // 恢复码消费使用数据库行锁，同一个恢复码在并发请求中只能成功一次。
        assertEquals(1, results.stream().filter(Boolean::booleanValue).count());
        assertEquals(1, results.stream().filter(value -> !value).count());
    }

    private UserRepository.AuthUser admin() {
        UserRepository.AuthUser user = users.findAuthUserByUsername("admin").orElseThrow();
        adminId = user.id();
        return user;
    }

    private static <T> List<T> runTogether(ConcurrentOperation<T> operation) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<T>> futures = List.of(
                    pool.submit(() -> awaitAndRun(start, operation)),
                    pool.submit(() -> awaitAndRun(start, operation)));
            start.countDown();
            List<T> results = new ArrayList<>(2);
            for (Future<T> future : futures) results.add(get(future));
            return results;
        } finally {
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    private static <T> T awaitAndRun(CountDownLatch start, ConcurrentOperation<T> operation) throws Exception {
        assertTrue(start.await(10, TimeUnit.SECONDS));
        return operation.run();
    }

    private static <T> T get(Future<T> future) throws Exception {
        try {
            return future.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException error) {
            throw new AssertionError("database concurrency operation failed", error.getCause());
        }
    }

    @FunctionalInterface
    private interface ConcurrentOperation<T> {
        T run() throws Exception;
    }
}
