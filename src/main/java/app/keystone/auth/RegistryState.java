package app.keystone.auth;

/** 集中校验 JWK registry 的状态和公开字段，避免不同入口接受不同值。 */
final class RegistryState {
    static final String ACTIVE = "ACTIVE";
    static final String RETIRING = "RETIRING";

    private RegistryState() {
    }

    static String requireState(String value) {
        if (ACTIVE.equals(value) || RETIRING.equals(value)) return value;
        throw new IllegalArgumentException("JWT key state must be ACTIVE or RETIRING");
    }

    static String requireKeyId(String value) {
        return AccessTokenService.requireKeyId(value);
    }

    static String requireValue(String value, String name) {
        if (value == null || value.isBlank() || value.length() > 4096) {
            throw new IllegalArgumentException("JWT key " + name + " is invalid");
        }
        return value;
    }

    static boolean usable(String state, java.time.Instant expiry, java.time.Instant now) {
        return (ACTIVE.equals(state) || RETIRING.equals(state)) && (expiry == null || expiry.isAfter(now));
    }
}
