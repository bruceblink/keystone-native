package app.keystone.notification;

import app.keystone.identity.UuidValues;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.panache.common.Page;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;

/** 只通过收件人 ID 查询或修改站内通知。 */
@ApplicationScoped
public class NotificationRepository implements PanacheRepositoryBase<NotificationEntity, java.util.UUID> {
    private static final int PAGE_SIZE = 50;

    /** 在调用方事务内写入安全通知；失败时让调用方的业务事务一起回滚。 */
    @Transactional
    public void create(String recipientUserId, String type, String title, String content) {
        persistAndFlush(new NotificationEntity(
                UuidValues.v7(), recipientUserId, type, title, content));
    }

    /** 无分页参数时返回最新 50 条，并统计当前用户的全部未读记录。 */
    @Transactional
    public NotificationInbox listForUser(String recipientUserId) {
        String owner = UuidValues.requireCanonical(recipientUserId);
        List<NotificationItem> items = find(
                "recipientUserId = ?1 order by createdAt desc, id desc", owner)
                .page(Page.of(0, PAGE_SIZE))
                .list()
                .stream()
                .map(NotificationRepository::toItem)
                .toList();
        return new NotificationInbox(items, unreadCount(owner));
    }

    /** 返回固定 50 条的指定页，并多取一条判断是否还有后续通知。 */
    @Transactional
    public NotificationInbox listForUser(String recipientUserId, int page) {
        String owner = UuidValues.requireCanonical(recipientUserId);
        int firstResult = (page - 1) * PAGE_SIZE;
        List<NotificationEntity> rows = find(
                "recipientUserId = ?1 order by createdAt desc, id desc", owner)
                .range(firstResult, firstResult + PAGE_SIZE)
                .list();
        boolean hasMore = rows.size() > PAGE_SIZE;
        List<NotificationItem> items = rows.stream()
                .limit(PAGE_SIZE)
                .map(NotificationRepository::toItem)
                .toList();
        return new NotificationInbox(items, unreadCount(owner), page, hasMore);
    }

    /** 详情查询将通知 ID 和认证收件人同时放入数据库条件。 */
    @Transactional
    public NotificationItem findForUser(String recipientUserId, String notificationId) {
        return toItem(requireForUser(recipientUserId, notificationId, false));
    }

    /** 已读更新加行锁并限制收件人，重复调用不会改变首次已读时间。 */
    @Transactional
    public NotificationItem markReadForUser(String recipientUserId, String notificationId) {
        NotificationEntity notification = requireForUser(recipientUserId, notificationId, true);
        notification.markRead(Instant.now());
        flush();
        // 重新读取数据库最终值，避免 MySQL DATETIME 精度截断造成响应与详情不一致。
        getEntityManager().refresh(notification);
        return toItem(notification);
    }

    private NotificationEntity requireForUser(String recipientUserId, String notificationId, boolean lock) {
        String owner = UuidValues.requireCanonical(recipientUserId);
        final java.util.UUID id;
        try {
            id = UuidValues.parse(notificationId);
        } catch (RuntimeException invalidId) {
            throw new NoSuchElementException("notification not found");
        }
        var query = find("id = ?1 and recipientUserId = ?2", id, owner);
        if (lock) query = query.withLock(LockModeType.PESSIMISTIC_WRITE);
        NotificationEntity notification = query.firstResult();
        if (notification == null) throw new NoSuchElementException("notification not found");
        return notification;
    }

    private static NotificationItem toItem(NotificationEntity notification) {
        return new NotificationItem(
                notification.id(),
                notification.type(),
                notification.title(),
                notification.content(),
                notification.createdAt(),
                notification.readAt());
    }

    private long unreadCount(String owner) {
        return count("recipientUserId = ?1 and readAt is null", owner);
    }
}
