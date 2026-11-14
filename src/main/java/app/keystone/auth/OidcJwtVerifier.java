package app.keystone.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Base64;

/** 只接受 RS256 的 OIDC ID Token，并校验签名、issuer、audience、nonce 和时间窗口。 */
final class OidcJwtVerifier {
    private OidcJwtVerifier() {}

    static Claims verify(String token, OidcConfiguration config, HttpClient client,
                         ObjectMapper mapper, String expectedNonceHash) {
        try {
            String[] parts = token == null ? new String[0] : token.split("\\.", -1);
            if (parts.length != 3) throw invalid();
            JsonNode header = mapper.readTree(decode(parts[0]));
            JsonNode claims = mapper.readTree(decode(parts[1]));
            if (!header.path("alg").isTextual() || !"RS256".equals(header.path("alg").asText())
                    || !header.path("kid").isTextual() || header.path("kid").asText().isBlank()
                    || (header.has("typ") && !"JWT".equals(header.path("typ").asText()))) throw invalid();
            RSAPublicKey key = findKey(header.path("kid").asText(), config, client, mapper);
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(key);
            signature.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!signature.verify(Base64.getUrlDecoder().decode(parts[2]))) throw invalid();
            validateClaims(claims, config, expectedNonceHash);
            return new Claims(claims.path("sub").asText(), claims.path("email").asText(null), claims.path("name").asText(null));
        } catch (OidcException e) {
            throw e;
        } catch (Exception e) {
            throw invalid();
        }
    }

    private static RSAPublicKey findKey(String kid, OidcConfiguration config, HttpClient client, ObjectMapper mapper) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(config.jwksUri()))
                .timeout(java.time.Duration.ofSeconds(config.httpTimeoutSeconds())).GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() != 200) throw invalid();
        JsonNode keys = mapper.readTree(response.body()).path("keys");
        if (!keys.isArray()) throw invalid();
        for (JsonNode key : keys) {
            if (!key.path("kid").isTextual() || !key.path("kty").isTextual()
                    || !kid.equals(key.path("kid").asText()) || !"RSA".equals(key.path("kty").asText())) continue;
            if (!"RS256".equals(key.path("alg").asText()) && !key.path("alg").isMissingNode()) throw invalid();
            if (!key.path("use").isMissingNode() && !"sig".equals(key.path("use").asText())) throw invalid();
            BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(key.path("n").asText()));
            BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(key.path("e").asText()));
            if (modulus.bitLength() < 2048 || exponent.signum() <= 0) throw invalid();
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
        }
        throw invalid();
    }

    private static void validateClaims(JsonNode claims, OidcConfiguration config, String expectedNonceHash) {
        long now = Instant.now().getEpochSecond();
        if (!claims.path("sub").isTextual() || claims.path("sub").asText().isBlank()
                || !claims.path("iss").isTextual() || !config.issuer().equals(claims.path("iss").asText())) throw invalid();
        JsonNode audience = claims.path("aud");
        boolean audienceMatches = audience.isTextual() ? config.audience().equals(audience.asText()) : audience.isArray() && contains(audience, config.audience());
        JsonNode exp = claims.path("exp");
        JsonNode iat = claims.path("iat");
        if (!audienceMatches || !exp.isIntegralNumber() || !iat.isIntegralNumber()
                || exp.asLong() <= now || iat.asLong() > now + 30 || !claims.path("nonce").isTextual() || claims.path("nonce").asText().isBlank()
                || !java.security.MessageDigest.isEqual(sha256(claims.path("nonce").asText()).getBytes(StandardCharsets.US_ASCII), expectedNonceHash.getBytes(StandardCharsets.US_ASCII))) throw invalid();
        if (audience.isArray() && audience.size() > 1 && !config.audience().equals(claims.path("azp").asText())) throw invalid();
    }

    private static boolean contains(JsonNode values, String expected) {
        for (JsonNode value : values) if (expected.equals(value.asText())) return true;
        return false;
    }

    static String sha256(String value) {
        try { return java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException("SHA-256 is unavailable", e); }
    }

    private static String decode(String value) { return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8); }
    private static OidcException invalid() { return new OidcException("invalid OIDC identity token"); }
    static final class OidcException extends RuntimeException { OidcException(String message) { super(message); } }
    record Claims(String subject, String email, String name) {}
}
