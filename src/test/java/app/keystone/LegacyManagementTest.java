package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class LegacyManagementTest extends AuthTestFixture {
    @Test
    void originalManagementRoutesAreAvailable() {
        String token = given().contentType(JSON).body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        String[] paths = {"/system/depts", "/system/depts/dropdown", "/system/dict/types", "/system/dict/data/list", "/system/configs", "/system/menus", "/system/menus/dropdown", "/system/notices", "/system/post/list"};
        for (String path : paths) given().auth().oauth2(token).when().get(path).then().statusCode(200).body("success", is(true));
        given().auth().oauth2(token).when().delete("/system/configs/cache").then().statusCode(200).body("data.cleared", is(true));

        int id = given().auth().oauth2(token).contentType(JSON)
                .body("{\"postCode\":\"compat-" + System.nanoTime() + "\",\"postName\":\"Compatibility Post\",\"postSort\":1}")
                .when().post("/system/post").then().statusCode(201).extract().path("data.id");
        given().auth().oauth2(token).when().get("/system/post/" + id).then().statusCode(200).body("data.name", is("Compatibility Post"));
        given().auth().oauth2(token).when().delete("/system/post?ids=" + id).then().statusCode(200).body("data.deleted", is(1));
    }
}
