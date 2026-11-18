package app.keystone;

import app.keystone.auth.RoleAdminOrmRepository;
import app.keystone.auth.AuthorizationContext;
import app.keystone.auth.AuthorizationService;
import app.keystone.role.Role;
import io.quarkus.test.junit.QuarkusMock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 使用隔离 MySQL 中的真实角色和用户记录验证 capabilities HTTP 接口。 */
@QuarkusTest
class AuthCapabilitiesResourceHttpTest extends AuthTestFixture {
    private static final Set<String> RESOURCE_NAMES = Set.of(
            "user", "department", "profile", "role", "post", "menu", "config", "dictionary",
            "notice", "job", "audit", "session", "api-key");

    @Inject RoleAdminOrmRepository roles;

    @Test
    void returnsEnabledMultiRolePermissionUnionAndScopeEntryRules() {
        String admin = login("admin");
        List<Role> createdRoles = new ArrayList<>();
        String userId = null;
        String ownerUserId = null;
        String selfUserId = null;
        try {
            Role self = createRole(createdRoles, "SELF", true, List.of("user:read", "notice:read"));
            Role owner = createRole(createdRoles, "OWNER", true, List.of("api-key:read", "job:read"));
            Role disabled = createRole(createdRoles, "ALL", true, List.of("role:read"));
            String username = "caps_union_" + System.nanoTime();
            userId = createUser(admin, username, List.of(self.code(), owner.code(), disabled.code()));
            roles.updateRoleById(disabled.id(), null, false, null, null);
            String ownerUsername = "caps_owner_" + System.nanoTime();
            ownerUserId = createUser(admin, ownerUsername, List.of(owner.code()));
            String selfUsername = "caps_self_" + System.nanoTime();
            selfUserId = createUser(admin, selfUsername, List.of(self.code()));

            String token = login(username);
            var response = capabilities(token);
            assertEquals(List.of("api-key:read", "job:read", "notice:read", "user:read"),
                    response.jsonPath().getList("data.permissions", String.class));
            Map<String, Boolean> resources = response.jsonPath().getMap("data.resources");
            assertEquals(RESOURCE_NAMES, resources.keySet());
            assertTrue(resources.get("user"));
            assertTrue(resources.get("department"));
            assertTrue(resources.get("profile"));
            assertTrue(resources.get("notice"));
            assertTrue(resources.get("job"));
            assertTrue(resources.get("api-key"));
            for (String resource : List.of("role", "post", "menu", "config", "dictionary", "audit", "session")) {
                assertFalse(resources.get(resource), resource + " requires ALL/TENANT scope");
            }
            assertEquals("no-store", response.getHeader("Cache-Control"));

            Map<String, Boolean> ownerOnly = capabilities(login(ownerUsername)).jsonPath().getMap("data.resources");
            assertTrue(ownerOnly.get("notice"));
            assertTrue(ownerOnly.get("job"));
            assertFalse(ownerOnly.get("api-key"));
            assertFalse(ownerOnly.get("profile"));

            Map<String, Boolean> selfOnly = capabilities(login(selfUsername)).jsonPath().getMap("data.resources");
            assertTrue(selfOnly.get("api-key"));
            assertTrue(selfOnly.get("profile"));
            assertFalse(selfOnly.get("notice"));
            assertFalse(selfOnly.get("job"));
        } finally {
            List<String> createdUsers = java.util.Arrays.stream(new String[]{userId, ownerUserId, selfUserId})
                    .filter(java.util.Objects::nonNull)
                    .toList();
            cleanup(admin, createdUsers, createdRoles);
        }
    }

    @Test
    void allScopeAllowsEveryResourceAndAnEmptyRoleSetKeepsOnlyFilteredLists() {
        String admin = login("admin");
        List<Role> createdRoles = new ArrayList<>();
        String allUserId = null;
        String emptyUserId = null;
        try {
            Role all = createRole(createdRoles, "ALL", true, List.of("user:read"));
            String allUsername = "caps_all_" + System.nanoTime();
            allUserId = createUser(admin, allUsername, List.of(all.code()));
            String emptyUsername = "caps_empty_" + System.nanoTime();
            emptyUserId = createUser(admin, emptyUsername, List.of());

            Map<String, Boolean> allResources = capabilities(login(allUsername)).jsonPath().getMap("data.resources");
            assertEquals(RESOURCE_NAMES, allResources.keySet());
            assertTrue(allResources.values().stream().allMatch(Boolean.TRUE::equals));

            var emptyResponse = capabilities(login(emptyUsername));
            assertEquals(List.of(), emptyResponse.jsonPath().getList("data.permissions"));
            Map<String, Boolean> emptyResources = emptyResponse.jsonPath().getMap("data.resources");
            assertTrue(emptyResources.get("user"));
            assertTrue(emptyResources.get("department"));
            for (String resource : RESOURCE_NAMES.stream()
                    .filter(name -> !name.equals("user") && !name.equals("department")).toList()) {
                assertFalse(emptyResources.get(resource), resource + " must fail closed for an empty scope");
            }
        } finally {
            cleanup(admin, allUserId, createdRoles);
            cleanup(admin, emptyUserId, List.of());
        }
    }

    @Test
    void permissionChangesInvalidateOldSessionAndAppearAfterFreshLogin() {
        String admin = login("admin");
        List<Role> createdRoles = new ArrayList<>();
        String userId = null;
        try {
            Role role = createRole(createdRoles, "SELF", true, List.of("user:read"));
            String username = "caps_dynamic_" + System.nanoTime();
            userId = createUser(admin, username, List.of(role.code()));
            String oldToken = login(username);
            assertEquals(List.of("user:read"), capabilities(oldToken).jsonPath().getList("data.permissions"));

            roles.assignPermissionsById(role.id(), List.of("user:read", "api-key:read"));
            given().auth().oauth2(oldToken)
                    .when().get("/v1/auth/me/capabilities")
                    .then().statusCode(401)
                    .body("error.code", org.hamcrest.Matchers.is("session_revoked"))
                    .header("Cache-Control", org.hamcrest.Matchers.is("no-store"));

            String freshToken = login(username);
            assertEquals(List.of("api-key:read", "user:read"),
                    capabilities(freshToken).jsonPath().getList("data.permissions"));
        } finally {
            cleanup(admin, userId, createdRoles);
        }
    }

    @Test
    void anonymousAndApiKeyCredentialsCannotReadHumanCapabilities() {
        given().when().get("/v1/auth/me/capabilities")
                .then().statusCode(401)
                .body("error.code", org.hamcrest.Matchers.is("authentication_required"))
                .header("Cache-Control", org.hamcrest.Matchers.is("no-store"));

        String admin = login("admin");
        var issued = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"name\":\"capabilities-" + System.nanoTime() + "\",\"scopes\":[\"user:read\"]}")
                .when().post("/v1/api-keys")
                .then().statusCode(201)
                .extract();
        String key = issued.path("data.apiKey");
        String keyId = issued.path("data.id");
        try {
            given().header("Authorization", "ApiKey " + key)
                    .when().get("/v1/auth/me/capabilities")
                    .then().statusCode(403)
                    .body("error.code", org.hamcrest.Matchers.is("permission_denied"))
                    .header("Cache-Control", org.hamcrest.Matchers.is("no-store"));
        } finally {
            given().auth().oauth2(admin).when().delete("/v1/api-keys/" + keyId).then().statusCode(200);
        }
    }

    @Test
    void persistenceFailureDuringAuthorizationMapsToUnavailableAndNoStore() {
        String admin = login("admin");
        QuarkusMock.installMockForType(new AuthorizationService() {
            @Override
            public AuthorizationContext context(io.quarkus.security.identity.SecurityIdentity identity) {
                throw new jakarta.persistence.PersistenceException("simulated ORM query failure");
            }
        }, AuthorizationService.class);

        given().auth().oauth2(admin)
                .when().get("/v1/auth/me/capabilities")
                .then().statusCode(503)
                .body("error.code", org.hamcrest.Matchers.is("authorization_unavailable"))
                .header("Cache-Control", org.hamcrest.Matchers.is("no-store"));
    }

    private Role createRole(List<Role> created, String scope, boolean enabled, List<String> permissions) {
        String code = "CAPS_" + System.nanoTime();
        Role role = roles.createRole(code, "Capabilities " + code, enabled);
        roles.updateRoleById(role.id(), null, null, scope, null);
        roles.assignPermissionsById(role.id(), permissions);
        created.add(role);
        return role;
    }

    private static String createUser(String admin, String username, List<String> roleCodes) {
        return given().auth().oauth2(admin).contentType(JSON)
                .body(Map.of("username", username, "password", "password", "displayName", "Capabilities user",
                        "roleCodes", roleCodes))
                .when().post("/v1/users")
                .then().statusCode(201)
                .extract().path("data.id");
    }

    private static io.restassured.response.Response capabilities(String token) {
        return given().auth().oauth2(token)
                .when().get("/v1/auth/me/capabilities")
                .then().statusCode(200)
                .extract().response();
    }

    private static String login(String username) {
        return given().contentType(JSON)
                .body(Map.of("username", username, "password", "password", "forceLogin", true))
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }

    private void cleanup(String admin, String userId, List<Role> created) {
        cleanup(admin, userId == null ? List.of() : List.of(userId), created);
    }

    private void cleanup(String admin, List<String> userIds, List<Role> created) {
        for (String userId : userIds) {
            if (userId == null) continue;
            given().auth().oauth2(admin).when().delete("/v1/users/" + userId).then().statusCode(200);
        }
        for (int index = created.size() - 1; index >= 0; index--) {
            roles.deleteRoleById(created.get(index).id());
        }
    }
}
