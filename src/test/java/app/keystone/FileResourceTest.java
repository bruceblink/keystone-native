package app.keystone;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

@QuarkusTest
class FileResourceTest {
    @Test
    void authenticatedUploadAndSafeDownloadWork() {
        String token = given().contentType("application/json").body("{\"username\":\"admin\",\"password\":\"password\",\"forceLogin\":true}")
                .when().post("/login").then().statusCode(200).extract().path("data.token");
        String fileName = given().auth().oauth2(token).multiPart("file", "hello.txt", "hello".getBytes(StandardCharsets.UTF_8), "text/plain")
                .when().post("/file/upload").then().statusCode(200).body("data.originalFilename", is("hello.txt")).extract().path("data.fileName");
        given().auth().oauth2(token).when().get("/file/download?fileName=" + fileName).then().statusCode(200).header("Content-Disposition", containsString("attachment"));
        given().auth().oauth2(token).when().get("/file/download?fileName=../application.properties").then().statusCode(400).body("success", is(false));
    }
}
