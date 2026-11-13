package app.keystone.audit;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import javax.sql.DataSource;

/** Persists security boundary events without storing credential material. */
@ApplicationScoped
public class SecurityEventRepository {
    @Inject DataSource dataSource;

    public void record(String eventType, String actor, String credentialType, String sourceIp,
                       String resource, String action, String outcome, String detail) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(
                "INSERT INTO sys_security_event(event_type, actor, credential_type, source_ip, resource, action, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")) {
            p.setString(1, bounded(eventType, 32));
            setNullable(p, 2, bounded(actor, 128));
            setNullable(p, 3, bounded(credentialType, 32));
            setNullable(p, 4, bounded(sourceIp, 64));
            setNullable(p, 5, bounded(resource, 128));
            setNullable(p, 6, bounded(action, 128));
            p.setString(7, bounded(outcome, 32));
            setNullable(p, 8, bounded(detail, 255));
            p.executeUpdate();
        } catch (Exception e) {
            throw new IllegalStateException("Could not record security event", e);
        }
    }

    private static void setNullable(java.sql.PreparedStatement p, int index, String value) throws Exception {
        if (value == null || value.isBlank()) p.setNull(index, java.sql.Types.VARCHAR); else p.setString(index, value);
    }

    private static String bounded(String value, int maxLength) {
        if (value == null) return null;
        String normalized = value.trim();
        if (normalized.length() > maxLength) throw new IllegalArgumentException("security event field is too long");
        return normalized;
    }
}
