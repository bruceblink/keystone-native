package app.keystone.notification;

import java.util.List;

/** 当前用户的最近通知和全部未读数量。 */
public record NotificationInbox(List<NotificationItem> items, long unreadCount) {
}
