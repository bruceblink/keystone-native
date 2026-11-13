package app.keystone.notice;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.Instant;

/** 映射公告内容和发布状态；数据库表结构由 Flyway 管理。 */
@Entity
@Table(name = "sys_notice")
public class NoticeEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Lob
    @Column(nullable = false)
    private String content;

    @Column(name = "notice_type", nullable = false, length = 32)
    private String noticeType;

    @Column(nullable = false)
    private boolean published;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "publish_at")
    private Instant publishAt;

    @Column(name = "created_by", nullable = false, length = 64)
    private String createdBy;

    @Column(name = "created_at", nullable = false, insertable = false, updatable = false)
    private Instant createdAt;

    protected NoticeEntity() {
    }

    NoticeEntity(String title, String content, String type, String createdBy) {
        this.title = title.trim();
        this.content = content;
        this.noticeType = type == null ? "NOTICE" : type;
        this.createdBy = createdBy;
        this.enabled = true;
    }

    void update(String newTitle, String newContent, String newType, Boolean newEnabled) {
        if (newTitle != null && !newTitle.isBlank()) title = newTitle.trim();
        if (newContent != null) content = newContent;
        if (newType != null) noticeType = newType;
        if (newEnabled != null) enabled = newEnabled;
    }

    void publish(boolean value) {
        published = value;
        publishAt = value ? Instant.now() : null;
    }

    Notice toModel() {
        return new Notice(id, title, content, noticeType, published, enabled, publishAt, createdBy, createdAt);
    }
}
