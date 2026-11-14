package app.keystone.auth;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.is;

/** 验证公开 JWK 只从已持久化 registry 发布。 */
@QuarkusTest
class JwtKeyRegistryHttpTest {
    @Test
    void publishesRegisteredKeySet() {
        given().when().get("/.well-known/jwks.json")
                .then().statusCode(200)
                .body("keys.size()", greaterThan(0))
                .body("keys[0].kty", is("RSA"))
                .body("keys[0].alg", is("RS256"))
                .body("keys[0].use", is("sig"));
    }
}
