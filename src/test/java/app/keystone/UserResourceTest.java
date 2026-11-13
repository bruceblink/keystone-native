package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.JSON;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.not;

@QuarkusTest
class UserResourceTest extends AuthTestFixture {
    @Test
    void adminCanFilterAndUpdateProfileFieldsButRegularUsersOnlySeeTheirOwnRecord() {
        String admin = login("admin", "password");
        String username = "profile_" + System.nanoTime();
        String peerUsername = "profile_peer_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Profile User\",\"email\":\"old@example.test\",\"phoneNumber\":\"13800000000\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).body("data.email", is("old@example.test")).extract().path("data.id");
        String peerId = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + peerUsername + "\",\"password\":\"password\",\"displayName\":\"Peer User\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");

        given().auth().oauth2(admin).when().get("/v1/users?username=" + username).then().statusCode(200).body("data.items", not(empty()));
        String user = login(username, "password");
        given().auth().oauth2(user).when().get("/v1/users").then().statusCode(200)
                .body("data.items.size()", is(1))
                .body("data.items[0].username", is(username));
        given().auth().oauth2(user).when().get("/v1/users/" + peerId).then().statusCode(404);
        given().auth().oauth2(user).contentType(JSON)
                .body("{\"displayName\":\"Updated User\",\"email\":\"new@example.test\",\"phoneNumber\":\"13900000000\",\"sex\":1}")
                .when().put("/v1/profile").then().statusCode(200).body("data.email", is("new@example.test"));
        given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
        given().auth().oauth2(admin).when().delete("/v1/users/" + peerId).then().statusCode(200);
    }

    @Test
    void changingUserRolesInvalidatesExistingAccessToken() {
        String admin = login("admin", "password");
        String username = "permission_version_" + System.nanoTime();
        String id = given().auth().oauth2(admin).contentType(JSON)
                .body("{\"username\":\"" + username + "\",\"password\":\"password\",\"displayName\":\"Version User\",\"roleCodes\":[\"USER\"]}")
                .when().post("/v1/users").then().statusCode(201).extract().path("data.id");
        String user = login(username, "password");
        given().auth().oauth2(admin).contentType(JSON)
                .body("{\"roleCodes\":[\"USER\"]}")
                .when().put("/v1/users/" + id).then().statusCode(200);
        given().auth().oauth2(user).when().get("/v1/profile").then().statusCode(401);
        given().auth().oauth2(admin).when().delete("/v1/users/" + id).then().statusCode(200);
    }

    private static String login(String username, String password) {
        return given().contentType(JSON).body("{\"username\":\"" + username + "\",\"password\":\"" + password + "\",\"forceLogin\":true}")
                .when().post("/v1/auth/login").then().statusCode(200).extract().path("data.accessToken");
    }
}
