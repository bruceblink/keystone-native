package app.keystone.notification;

import java.time.Instant;

/** 站内通知的公开数据结构；不包含收件人和内部事件来源字段。 */
public record NotificationItem(
        String id,
        String type,
        String title,
        String content,
        Instant createdAt,
        Instant readAt) {
}
