package app.keystone.auth;

import app.keystone.audit.SecurityEventRepository;
import app.keystone.user.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import io.quarkus.scheduler.Scheduled;
import org.jboss.logging.Logger;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/** 编排 OIDC 授权码、PKCE、ID Token 校验和本地会话创建。 */
@ApplicationScoped
public class OidcService {
    private static final Logger LOG = Logger.getLogger(OidcService.class);
    @Inject OidcConfiguration config;
    @Inject OidcAuthRequestRepository requests;
    @Inject app.keystone.auth.ApiKeyUserRepository users;
    @Inject SessionRepository sessions;
    @Inject AccessTokenService tokens;
    @Inject SecurityEventRepository securityEvents;
    @Inject ObjectMapper mapper;
    @Inject Instance<HttpClient> configuredClient;

    private HttpClient client;

    @PostConstruct
    void initialize() { if (config.enabled()) config.validate(); client = configuredClient.isResolvable() ? configuredClient.get() : HttpClient.newHttpClient(); }

    public URI authorize() {
        ensureEnabled();
        String state = randomValue(32);
        String verifier = randomValue(48);
        String codeChallenge = pkceChallenge(verifier);
        String redirectUri = config.redirectUri();
        String nonce = randomValue(32);
        requests.create(OidcJwtVerifier.sha256(state), OidcJwtVerifier.sha256(nonce), codeChallenge, verifier,
                config.clientId(), redirectUri, Instant.now().plusSeconds(config.requestTtlSeconds()));
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code"); params.put("client_id", config.clientId());
        params.put("redirect_uri", redirectUri); params.put("scope", "openid profile email");
        params.put("state", state); params.put("nonce", nonce); params.put("code_challenge", codeChallenge); params.put("code_challenge_method", "S256");
        return URI.create(config.authorizationEndpoint() + (config.authorizationEndpoint().contains("?") ? "&" : "?") + query(params));
    }

    public AuthResource.TokenResponse callback(String code, String state) {
        ensureEnabled();
        if (code == null || code.isBlank() || !validState(state)) throw new IllegalArgumentException("invalid OIDC callback");
        var request = consumeState(state);
        try {
            String idToken = exchangeCode(code, request.redirectUri(), request.codeVerifier());
            OidcJwtVerifier.Claims claims = OidcJwtVerifier.verify(idToken, config, client, mapper, request.nonceHash());
            var user = users.findAuthUserByOidc(config.issuer(), claims.subject()).orElseThrow(() -> new OidcJwtVerifier.OidcException("OIDC identity is not linked"));
            var session = sessions.create(user.id(), true, "oidc").orElseThrow(() -> new IllegalStateException("could not create OIDC session"));
            recordAllowed(user.username(), claims.subject());
            return tokens.issue(user, session.refreshToken(), session.accessTokenId(), session.sessionId(), session.clientId(), session.approvedScope(), session.refreshExpiresAt(), "AAL1", "oidc");
        } catch (OidcJwtVerifier.OidcException e) {
            recordDenied(e.getMessage());
            throw e;
        } catch (IllegalStateException e) {
            recordDenied("OIDC authentication state is unavailable");
            throw e;
        }
    }

    private OidcAuthRequestEntity consumeState(String state) {
        try {
            return requests.consume(OidcJwtVerifier.sha256(state), Instant.now())
                    .orElseThrow(() -> new OidcJwtVerifier.OidcException("invalid or expired OIDC state"));
        } catch (OidcJwtVerifier.OidcException e) {
            recordDenied(e.getMessage());
            throw e;
        }
    }

    private void recordAllowed(String actor, String subject) {
        recordEvent(actor, subject, "ALLOW", "OIDC login successful");
    }

    private void recordDenied(String detail) {
        recordEvent(null, null, "DENY", detail);
    }

    private void recordEvent(String actor, String subject, String outcome, String detail) {
        try {
            securityEvents.record("OIDC_LOGIN", actor, "OIDC", subject, null, "auth", "login", outcome,
                    SecurityEventRepository.Context.empty(), detail);
        } catch (RuntimeException e) {
            LOG.warn("OIDC security event could not be recorded", e);
        }
    }

    /** 消费 provider 错误回调中的状态，阻止错误响应被重复提交。 */
    public void cancel(String state) {
        if (config.enabled() && validState(state)) requests.cancel(OidcJwtVerifier.sha256(state), Instant.now());
    }

    /** 定期删除过期或已消费的短期请求，避免状态表无限增长。 */
    @Scheduled(every = "5m", identity = "oidc-auth-request-cleanup")
    void cleanupRequests() {
        if (!config.enabled()) return;
        try {
            requests.deleteExpired(Instant.now());
        } catch (RuntimeException e) {
            LOG.warn("OIDC authorization request cleanup failed", e);
        }
    }

    private String exchangeCode(String code, String redirectUri, String codeVerifier) {
        try {
            Map<String, String> form = new LinkedHashMap<>();
            form.put("grant_type", "authorization_code"); form.put("code", code);
            form.put("redirect_uri", redirectUri); form.put("client_id", config.clientId());
            form.put("code_verifier", codeVerifier);
            if (!config.clientSecret().isBlank()) form.put("client_secret", config.clientSecret());
            HttpRequest request = HttpRequest.newBuilder(URI.create(config.tokenEndpoint())).timeout(java.time.Duration.ofSeconds(config.httpTimeoutSeconds()))
                    .header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(query(form))).build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (response.statusCode() != 200) throw new OidcJwtVerifier.OidcException("OIDC token exchange failed");
            JsonNode body = mapper.readTree(response.body());
            String idToken = body.path("id_token").asText();
            if (idToken.isBlank()) throw new OidcJwtVerifier.OidcException("OIDC ID Token is missing");
            return idToken;
        } catch (OidcJwtVerifier.OidcException e) { throw e; }
        catch (Exception e) { throw new OidcJwtVerifier.OidcException("OIDC provider is unavailable"); }
    }

    private void ensureEnabled() { if (!config.enabled()) throw new IllegalStateException("OIDC is disabled"); }
    static boolean validState(String value) { return value != null && value.length() >= 16 && value.length() <= 512 && value.matches("[A-Za-z0-9._~-]+"); }
    static boolean validCodeChallenge(String value) { return value != null && value.length() >= 43 && value.length() <= 128 && value.matches("[A-Za-z0-9_-]+"); }
    static boolean validVerifier(String value) { return value != null && value.length() >= 43 && value.length() <= 128 && value.matches("[A-Za-z0-9._~-]+"); }
    static String pkceChallenge(String verifier) { return Base64.getUrlEncoder().withoutPadding().encodeToString(sha256Bytes(verifier)); }
    private static byte[] sha256Bytes(String value) { try { return java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII)); } catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); } }
    // 每次生成 OIDC 随机值时在运行时创建随机源，避免 native image 缓存随机种子。
    private static String randomValue(int bytes) { byte[] value = new byte[bytes]; new SecureRandom().nextBytes(value); return Base64.getUrlEncoder().withoutPadding().encodeToString(value); }
    private static String query(Map<String, String> params) { return params.entrySet().stream().map(entry -> encode(entry.getKey()) + "=" + encode(entry.getValue())).reduce((left, right) -> left + "&" + right).orElse(""); }
    private static String encode(String value) { return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20"); }
}
