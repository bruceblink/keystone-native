package app.keystone;

import app.keystone.auth.MfaService;
import app.keystone.auth.TotpService;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 通过真实 HTTP 验证业务权限用户的 step-up 和人类会话边界。 */
@QuarkusTest
class MfaStepUpResourceHttpTest extends AuthTestFixture {
    @Inject MfaService mfa;

    /** 只给用户授予 role:read 和 role:delete，验证其不能管理 MFA 但能完成自己的 step-up。 */
    @Test
    void businessPermissionUserCanStepUpWithoutMfaManagementPermission() {
        String admin = login("admin", "password");
        String username = "step_up_business_" + System.nanoTime();
        String businessRoleCode = "HTTP_STEP_UP_BUSINESS_" + System.nanoTime();
        String targetRoleCode = "HTTP_STEP_UP_TARGET_" + System.nanoTime();
        String businessRoleId = null;
        String targetRoleId = null;
        String userId = null;
        String apiKeyId = null;

        try {
            businessRoleId = createRole(admin, businessRoleCode);
            targetRoleId = createRole(admin, targetRoleCode);
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"permissions\":[\"role:read\",\"role:delete\"]}")
                    .when().put("/v1/roles/" + businessRoleId + "/permissions")
                    .then().statusCode(200).body("data.updated", is(true));

            userId = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Step-up business user\",\"roleCodes\":[\"ADMIN\"]}")
                    .when().post("/v1/users")
                    .then().statusCode(201).extract().path("data.id");
            String enrollmentSession = login(username, "password");
            var enrollment = given().auth().oauth2(enrollmentSession).contentType(JSON)
                    .when().post("/v1/auth/mfa/enroll")
                    .then().statusCode(201).extract();
            String secret = enrollment.path("data.secret");
            String enrollmentCode = new TotpService().code(secret, Instant.now());
            var enrollmentResult = given().auth().oauth2(enrollmentSession).contentType(JSON)
                    .body("{\"challengeId\":\"" + enrollment.path("data.challengeId")
                            + "\",\"code\":\"" + enrollmentCode + "\"}")
                    .when().post("/v1/auth/mfa/enroll/verify")
                    .then().statusCode(200).extract();
            String recoveryCode = enrollmentResult.path("data.recoveryCodes[0]");

            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"roleCodes\":[\"" + businessRoleCode + "\"]}")
                    .when().put("/v1/users/" + userId)
                    .then().statusCode(200);
            List<String> permissions = given().auth().oauth2(admin).queryParam("keyword", businessRoleCode)
                    .when().get("/v1/roles")
                    .then().statusCode(200).extract().path("data.items[0].permissions");
            assertEquals(Set.of("role:read", "role:delete"), new HashSet<>(permissions));

            String aal1 = login(username, "password");
            // 先签发 AAL1，再开启强制 MFA；管理接口会撤销会话，此处要保留待 step-up 的现有会话。
            assertTrue(mfa.setRequired(userId, true));
            given().auth().oauth2(aal1).queryParam("keyword", targetRoleCode)
                    .when().get("/v1/roles")
                    .then().statusCode(200).body("data.items.size()", is(1));

            given().contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(401);
            given().contentType(JSON)
                    .body("{\"challengeId\":\"not-a-real-challenge\",\"code\":\"000000\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(401);
            given().header("Authorization", "Bearer invalid").contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(401);
            given().header("Authorization", "Bearer invalid").contentType(JSON)
                    .body("{\"challengeId\":\"not-a-real-challenge\",\"code\":\"000000\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(401);

            var apiKey = given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"name\":\"step-up-boundary-" + System.nanoTime()
                            + "\",\"scopes\":[\"role:read\",\"role:delete\"]}")
                    .when().post("/v1/api-keys").then().statusCode(201).extract();
            apiKeyId = apiKey.path("data.id");
            String apiKeySecret = apiKey.path("data.apiKey");
            given().header("Authorization", "ApiKey " + apiKeySecret).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(403)
                    .body("error.code", is("permission_denied"));
            given().header("Authorization", "ApiKey " + apiKeySecret).contentType(JSON)
                    .body("{\"challengeId\":\"not-a-real-challenge\",\"code\":\"000000\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(403)
                    .body("error.code", is("permission_denied"));

            var challenge = given().auth().oauth2(aal1).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(201).extract();
            String challengeId = challenge.path("data.challengeId");
            String stepUpCode = new TotpService().code(secret, Instant.now().plusSeconds(30));
            given().auth().oauth2(admin).contentType(JSON)
                    .body("{\"challengeId\":\"" + challengeId + "\",\"code\":\"" + stepUpCode + "\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(401)
                    .body("error.code", is("mfa_challenge_invalid"));
            given().auth().oauth2(aal1).when().delete("/v1/roles/" + targetRoleId)
                    .then().statusCode(403).body("error.code", is("mfa_required"));

            var upgraded = given().auth().oauth2(aal1).contentType(JSON)
                    .body("{\"challengeId\":\"" + challengeId + "\",\"code\":\"" + stepUpCode + "\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(200)
                    .body("data.authenticationLevel", is("AAL2")).extract();
            String aal2 = upgraded.path("data.accessToken");

            given().auth().oauth2(aal2).contentType(JSON)
                    .body("{\"required\":false}")
                    .when().put("/v1/auth/mfa/policy/" + userId).then().statusCode(403)
                    .body("error.code", is("permission_denied"));
            given().auth().oauth2(aal2).contentType(JSON).body("{}").when().post("/v1/auth/mfa/enroll").then().statusCode(403)
                    .body("error.code", is("permission_denied"));
            given().auth().oauth2(aal2).when().delete("/v1/roles/" + targetRoleId)
                    .then().statusCode(200).body("data.deleted", is(true));
            targetRoleId = null;

            var nextChallenge = given().auth().oauth2(aal2).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(201).extract();
            String nextChallengeId = nextChallenge.path("data.challengeId");
            for (int request = 0; request < 8; request++) {
                given().auth().oauth2(aal2).contentType(JSON).body("{}")
                        .when().post("/v1/auth/mfa/step-up").then().statusCode(201);
            }
            given().auth().oauth2(aal2).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(429)
                    .body("error.code", is("rate_limited"));
            given().auth().oauth2(aal1).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(401);

            var loginChallenge = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"forceLogin\":true}")
                    .when().post("/v1/auth/login").then().statusCode(401)
                    .body("message", is("MFA_REQUIRED")).extract();
            var secondSession = given().contentType(JSON)
                    .body("{\"username\":\"" + username + "\",\"challengeId\":\""
                            + loginChallenge.path("data.challengeId") + "\",\"code\":\"" + recoveryCode
                            + "\",\"forceLogin\":true}")
                    .when().post("/v1/auth/mfa/verify").then().statusCode(200).extract();
            String secondSessionToken = secondSession.path("data.accessToken");
            String nextStepUpCode = new TotpService().code(secret, Instant.now().plusSeconds(60));
            given().auth().oauth2(secondSessionToken).contentType(JSON)
                    .body("{\"challengeId\":\"" + nextChallengeId + "\",\"code\":\"" + nextStepUpCode + "\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(401)
                    .body("error.code", is("mfa_challenge_invalid"));
            given().auth().oauth2(secondSessionToken).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(201);
            given().auth().oauth2(aal2).contentType(JSON).body("{}")
                    .when().post("/v1/auth/mfa/step-up").then().statusCode(401);
            given().auth().oauth2(aal2).contentType(JSON)
                    .body("{\"challengeId\":\"" + nextChallengeId + "\",\"code\":\"" + nextStepUpCode + "\"}")
                    .when().post("/v1/auth/mfa/step-up/verify").then().statusCode(401);
        } finally {
            if (apiKeyId != null) given().auth().oauth2(admin).when().delete("/v1/api-keys/" + apiKeyId).then().statusCode(200);
            if (userId != null) given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
            if (targetRoleId != null) given().auth().oauth2(admin).when().delete("/v1/roles/" + targetRoleId).then().statusCode(200);
            if (businessRoleId != null) given().auth().oauth2(admin).when().delete("/v1/roles/" + businessRoleId).then().statusCode(200);
        }
    }

    /** 创建本次验收使用的独立角色，避免触碰系统角色。 */
    private static String createRole(String admin, String code) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"" + code + "\",\"name\":\"" + code + "\"}")
                .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");
    }

    /** 以强制替换旧会话的方式登录，确保每次取得当前会话令牌。 */
    private static String login(String username, String password) {
        return given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
