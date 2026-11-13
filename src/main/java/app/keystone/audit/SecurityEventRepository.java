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
        record(eventType, actor, credentialType, null, sourceIp, resource, action, outcome, detail);
    }

    /** 记录非秘密凭据标识，便于区分同一主体下的多个 API Key。 */
    public void record(String eventType, String actor, String credentialType, String credentialId,
                       String sourceIp, String resource, String action, String outcome, String detail) {
        try (var c = dataSource.getConnection(); var p = c.prepareStatement(
                "INSERT INTO sys_security_event(event_type, actor, credential_type, credential_id, source_ip, resource, action, outcome, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            p.setString(1, bounded(eventType, 32));
            setNullable(p, 2, bounded(actor, 128));
            setNullable(p, 3, bounded(credentialType, 32));
            setNullable(p, 4, bounded(credentialId, 128));
            setNullable(p, 5, bounded(sourceIp, 64));
            setNullable(p, 6, bounded(resource, 128));
            setNullable(p, 7, bounded(action, 128));
            p.setString(8, bounded(outcome, 32));
            setNullable(p, 9, bounded(detail, 255));
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
