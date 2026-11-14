package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;

/** 通过真实 HTTP 和 MySQL 验证配置、字典写入的完整生命周期。 */
@QuarkusTest
class ManagementWriteResourceHttpTest extends AuthTestFixture {
    @Test
    void administratorCanCreateUpdateAndDeleteSystemConfig() {
        String token = login();
        String key = "http_cfg_" + shortId();
        boolean deleted = false;
        try {
            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"key\":\"" + key + "\",\"value\":\"initial\",\"description\":\"HTTP config\"}")
                    .when().post("/v1/configs")
                    .then().statusCode(201)
                    .body("data.key", is(key));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"value\":\"updated\",\"description\":\"Updated config\",\"enabled\":true}")
                    .when().put("/v1/configs/" + key)
                    .then().statusCode(200)
                    .body("data.value", is("updated"));

            given().auth().oauth2(token)
                    .when().delete("/v1/configs/" + key)
                    .then().statusCode(200)
                    .body("data.deleted", is(true));
            deleted = true;

            given().auth().oauth2(token)
                    .when().get("/v1/configs/" + key)
                    .then().statusCode(404);
        } finally {
            if (!deleted) {
                given().auth().oauth2(token).when().delete("/v1/configs/" + key);
            }
        }
    }

    @Test
    void administratorCanCreateUpdateAndDeleteDictionaryTypeAndItem() {
        String token = login();
        String typeCode = "http_dict_" + shortId();
        String itemId = null;
        boolean typeDeleted = false;
        try {
            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"code\":\"" + typeCode + "\",\"name\":\"HTTP dictionary\",\"enabled\":true}")
                    .when().post("/v1/dictionaries")
                    .then().statusCode(201)
                    .body("data.code", is(typeCode));

            itemId = given().auth().oauth2(token).contentType(JSON)
                    .body("{\"value\":\"created\",\"label\":\"Created\",\"sortOrder\":1,\"enabled\":true}")
                    .when().post("/v1/dictionaries/" + typeCode + "/items")
                    .then().statusCode(201)
                    .extract().path("data.id");

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"name\":\"HTTP dictionary updated\",\"enabled\":true}")
                    .when().put("/v1/dictionaries/types/" + typeCode)
                    .then().statusCode(200)
                    .body("data.name", is("HTTP dictionary updated"));

            given().auth().oauth2(token).contentType(JSON)
                    .body("{\"label\":\"Updated\",\"sortOrder\":2,\"enabled\":true}")
                    .when().put("/v1/dictionaries/items/" + itemId)
                    .then().statusCode(200)
                    .body("data.label", is("Updated"));

            given().auth().oauth2(token)
                    .when().delete("/v1/dictionaries/items/" + itemId)
                    .then().statusCode(200)
                    .body("data.deleted", is(true));
            itemId = null;

            given().auth().oauth2(token)
                    .when().delete("/v1/dictionaries/types/" + typeCode)
                    .then().statusCode(200)
                    .body("data.deleted", is(true));
            typeDeleted = true;
        } finally {
            if (itemId != null) {
                given().auth().oauth2(token).when().delete("/v1/dictionaries/items/" + itemId);
            }
            if (!typeDeleted) {
                given().auth().oauth2(token).when().delete("/v1/dictionaries/types/" + typeCode);
            }
        }
    }

    private static String shortId() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 12);
    }

    private static String login() {
        return given().contentType(JSON)
                .body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/v1/auth/login")
                .then().statusCode(200)
                .extract().path("data.accessToken");
    }
}
