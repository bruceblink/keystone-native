package app.keystone.notification;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

/** 当前用户的最近通知和全部未读数量。 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record NotificationInbox(List<NotificationItem> items, long unreadCount, Integer page, Boolean hasMore) {
    /** 无分页参数时使用旧响应字段，保持现有客户端的数据结构不变。 */
    public NotificationInbox(List<NotificationItem> items, long unreadCount) {
        this(items, unreadCount, null, null);
    }
}
