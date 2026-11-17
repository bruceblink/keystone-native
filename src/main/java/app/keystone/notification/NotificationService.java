package app.keystone.notification;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/** 将已确认的 API Key 生命周期操作写入所属用户的站内通知。 */
@ApplicationScoped
public class NotificationService {
    @Inject NotificationRepository notifications;

    /** API Key 明文、前缀和名称都不进入通知内容。 */
    public void apiKeyCreated(String recipientUserId) {
        notifications.create(recipientUserId, "api_key.created", "API Key 已签发", "一个 API Key 已成功签发。");
    }

    /** 轮换提示只说明旧密钥失效，不包含任何凭据材料。 */
    public void apiKeyRotated(String recipientUserId) {
        notifications.create(recipientUserId, "api_key.rotated", "API Key 已轮换", "一个 API Key 已轮换，旧密钥已失效。");
    }

    /** 撤销提示只在密钥首次从有效状态变为撤销状态时生成。 */
    public void apiKeyRevoked(String recipientUserId) {
        notifications.create(recipientUserId, "api_key.revoked", "API Key 已撤销", "一个 API Key 已撤销。");
    }
}
