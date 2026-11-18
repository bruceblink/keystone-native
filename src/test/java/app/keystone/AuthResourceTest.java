package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AuthResourceTest extends AuthTestFixture {

    @Test
    void adminCanLoginAndReceiveRefreshToken() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(200).body("success", is(true))
                .body("data.accessToken", not(emptyOrNullString()))
                .body("data.refreshToken", not(emptyOrNullString()))
                .body("data.token", nullValue())
                .body("data.sessionId", not(emptyOrNullString()))
                .body("data.clientId", is("web"))
                .body("data.roles[0]", is("ADMIN"));
    }

    @Test
    void acceptsPhoenixCompatibleRsaEncryptedLoginPassword() throws Exception {
        String publicKey = given().when().get("/v1/auth/rsa-public-key")
                .then().statusCode(200).extract().path("data.publicKey");
        byte[] der = java.util.Base64.getDecoder().decode(publicKey);
        var key = java.security.KeyFactory.getInstance("RSA")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(der));
        var cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
        String encrypted = java.util.Base64.getEncoder().encodeToString(cipher.doFinal("password".getBytes(java.nio.charset.StandardCharsets.UTF_8)));

        given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"" + encrypted + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200).body("data.accessToken", not(emptyOrNullString()));
    }

    @Test
    void accessTokenCarriesCanonicalAuthenticationClaims() throws Exception {
        String token = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(token.split("\\.")[1]), java.nio.charset.StandardCharsets.UTF_8);
        var claims = new com.fasterxml.jackson.databind.ObjectMapper().readTree(payload);
        assertEquals("access", claims.path("type").asText());
        assertEquals("AAL1", claims.path("aal").asText());
        assertTrue(claims.path("amr").isArray());
        assertEquals("pwd", claims.path("amr").get(0).asText());
    }

    @Test
    void invalidCredentialsAreRejected() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login")
                .then().statusCode(401).body("success", is(false));
    }

    @Test
    void loginDoesNotRevealWhetherUsernameExists() {
        var existing = given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login").then().extract().response();
        var missing = given().contentType(JSON)
                .body("{\"username\":\"missing_" + System.nanoTime() + "\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login").then().extract().response();

        assertEquals(401, existing.statusCode());
        assertEquals(401, missing.statusCode());
        assertEquals(existing.jsonPath().getString("error.code"), missing.jsonPath().getString("error.code"));
        assertEquals(existing.jsonPath().getString("message"), missing.jsonPath().getString("message"));
    }

    @Test
    void repeatedFailuresAreRateLimited() {
        String admin = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        String username = "rate_limit_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Rate Limit User\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        for (int i = 0; i < 10; i++) {
            int status = given().contentType(JSON).body("{\"username\":\"" + username + "\",\"password\":\"wrong\"}")
                    .when().post("/v1/auth/login").then().extract().statusCode();
            assertEquals(401, status);
        }
        given().contentType(JSON).body("{\"username\":\"" + username + "\",\"password\":\"wrong\"}")
                .when().post("/v1/auth/login").then().statusCode(429);
        given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
    }

    @Test
    void secondLoginIsRejectedUnlessExplicitlyForced() {
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200);
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(409).body("success", is(false));
        given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).body("data.accessToken", not(emptyOrNullString()));
    }

    @Test
    void refreshTokenRotatesAndLogoutRevokesIt() {
        var login = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract();
        String access = login.path("data.accessToken");
        String refresh = login.path("data.refreshToken");
        var rotated = given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(200).extract();
        String replacement = rotated.path("data.refreshToken");
        access = rotated.path("data.accessToken");
        given().auth().oauth2(access).contentType(JSON).body("{\"refreshToken\":\"" + replacement + "\"}")
                .when().post("/v1/auth/logout").then().statusCode(200);
        given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
        given().contentType(JSON).body("{\"refreshToken\":\"" + replacement + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
    }

    @Test
    void refreshClientMismatchRevokesTheWholeTokenFamily() {
        String refresh = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"clientId\":\"desktop\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.refreshToken");
        given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\",\"clientId\":\"mobile\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
        given().contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\",\"clientId\":\"desktop\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
    }

    @Test
    void logoutInvalidatesTheAccessTokenImmediately() {
        var response = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract();
        String access = response.path("data.accessToken");
        String refresh = response.path("data.refreshToken");
        given().auth().oauth2(access).when().get("/v1/profile").then().statusCode(200);
        given().auth().oauth2(access).contentType(JSON).body("{\"refreshToken\":\"" + refresh + "\"}")
                .when().post("/v1/auth/logout").then().statusCode(200);
        given().auth().oauth2(access).when().get("/v1/profile").then().statusCode(401);
    }

    @Test
    void lowPrivilegeRoleCanRevokeOnlyItsOwnSession() {
        String admin = given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        String roleCode = "LOGOUT_" + Long.toUnsignedString(System.nanoTime());
        String roleId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"code\":\"" + roleCode + "\",\"name\":\"Logout test\",\"enabled\":true}")
                .when().post("/v1/roles").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"permissions\":[\"user:read\"]}")
                .when().put("/v1/roles/" + roleId + "/permissions").then().statusCode(200);

        String username = "logout_" + Long.toUnsignedString(System.nanoTime());
        String userId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"Very-Strong-Password-9!\",\"displayName\":\"Logout test\",\"roleCodes\":[\"" + roleCode + "\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        var login = given().contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"Very-Strong-Password-9!\"}")
                .when().post("/v1/auth/login").then().statusCode(200).extract();
        String userAccess = login.path("data.accessToken");
        String userRefresh = login.path("data.refreshToken");

        given().auth().oauth2(userAccess).when().get("/v1/auth/me/capabilities")
                .then().statusCode(200).body("data.permissions", org.hamcrest.Matchers.not(org.hamcrest.Matchers.hasItem("session:revoke")));
        given().auth().oauth2(admin).when().get("/v1/auth/me/capabilities").then().statusCode(200);
        given().auth().oauth2(userAccess).contentType(JSON).when().post("/v1/auth/logout")
                .then().statusCode(200).body("data.loggedOut", is(true));
        given().auth().oauth2(userAccess).when().get("/v1/auth/me/capabilities")
                .then().statusCode(401).body("error.code", is("session_revoked"));
        given().contentType(JSON).body("{\"refreshToken\":\"" + userRefresh + "\"}")
                .when().post("/v1/auth/refresh").then().statusCode(401);
        given().auth().oauth2(admin).when().get("/v1/auth/me/capabilities").then().statusCode(200);

        given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
        given().auth().oauth2(admin).when().delete("/v1/roles/" + roleId).then().statusCode(200);
    }

    @Test
    void logoutKeepsApiKeyPermissionStatusAndRejectsAnonymousRequests() throws Exception {
        given().contentType(JSON).when().post("/v1/auth/logout")
                .then().statusCode(401).body("error.code", is("authentication_required"));

        String admin = given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
        var noScope = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"name\":\"logout-no-scope-" + System.nanoTime() + "\",\"scopes\":[\"api-key:read\"]}")
                .when().post("/v1/api-keys").then().statusCode(201).extract();
        var withScope = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"name\":\"logout-with-scope-" + System.nanoTime() + "\",\"scopes\":[\"session:revoke\"]}")
                .when().post("/v1/api-keys").then().statusCode(201).extract();
        String noScopeKey = noScope.path("data.apiKey");
        String noScopeId = noScope.path("data.id");
        String withScopeKey = withScope.path("data.apiKey");
        String withScopeId = withScope.path("data.id");
        try {
            given().header("Authorization", "ApiKey " + noScopeKey).contentType(JSON)
                    .when().post("/v1/auth/logout").then().statusCode(403)
                    .body("error.code", is("permission_denied"));
            given().header("Authorization", "ApiKey " + withScopeKey).contentType(JSON)
                    .when().post("/v1/auth/logout").then().statusCode(401)
                    .body("error.code", is("authentication_required"));

            try (var connection = dataSource.getConnection();
                 var statement = connection.prepareStatement("SELECT COUNT(*) FROM sys_security_event WHERE credential_id = ? AND event_type = 'AUTHORIZATION' AND resource = 'permission' AND action = 'session:revoke' AND outcome = 'DENIED' AND detail = 'permission denied'")) {
                statement.setString(1, noScopeId);
                try (var rows = statement.executeQuery()) {
                    assertTrue(rows.next());
                    assertEquals(1, rows.getInt(1));
                }
            }
        } finally {
            given().auth().oauth2(admin).when().delete("/v1/api-keys/" + noScopeId).then().statusCode(200);
            given().auth().oauth2(admin).when().delete("/v1/api-keys/" + withScopeId).then().statusCode(200);
        }
    }
}
