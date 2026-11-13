package app.keystone.notice;

import java.time.Instant;

public record Notice(String id, String title, String content, String noticeType, boolean published, boolean enabled, Instant publishAt, String createdBy, Instant createdAt) {}
