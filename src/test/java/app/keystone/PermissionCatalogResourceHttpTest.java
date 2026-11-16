package app.keystone;

import app.keystone.auth.PermissionCatalog;
import app.keystone.auth.PermissionCatalogResource;
import app.keystone.auth.RequiresPermission;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 验证管理端可动态读取 API Key 授权范围目录。 */
@QuarkusTest
class PermissionCatalogResourceHttpTest extends AuthTestFixture {
    @Test
    void administratorReadsCatalogWithGrantabilityMetadata() {
        String token = login();

        given().auth().oauth2(token)
                .when().get("/v1/permissions/catalog")
                .then().statusCode(200)
                .body("data.entries", hasSize(PermissionCatalog.values().size()))
                .body("data.entries.permission", hasItem("user:read"))
                .body("data.entries.find { it.permission == 'user:read' }.resource", is("user"))
                .body("data.entries.find { it.permission == 'user:read' }.action", is("read"))
                .body("data.entries.find { it.permission == 'user:read' }.registered", is(true))
                .body("data.entries.find { it.permission == 'user:read' }.allowed", is(true));
    }

    @Test
    void catalogRequiresAuthenticationAndUsesCanonicalRoute() {
        given().when().get("/v1/permissions/catalog").then().statusCode(401);
        given().when().get("/v1/permission-catalog").then().statusCode(404);
    }

    @Test
    void resourceDeclaresAnyCatalogPermissionBoundary() throws Exception {
        var method = Arrays.stream(PermissionCatalogResource.class.getDeclaredMethods())
                .filter(candidate -> candidate.isAnnotationPresent(GET.class))
                .findFirst().orElseThrow();
        org.junit.jupiter.api.Assertions.assertEquals("/v1/permissions", PermissionCatalogResource.class.getAnnotation(Path.class).value());
        org.junit.jupiter.api.Assertions.assertEquals("/catalog", method.getAnnotation(Path.class).value());
        org.junit.jupiter.api.Assertions.assertArrayEquals(
                new String[]{"api-key:create", "permission:read", "role:manage"},
                method.getAnnotation(RequiresPermission.class).any());
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
