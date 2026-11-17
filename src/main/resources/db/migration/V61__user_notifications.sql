-- 保存收件人隔离的站内通知；单条原子建表使 Flyway 记录失败后可安全重跑。
CREATE TABLE IF NOT EXISTS sys_notification (
  id BINARY(16) NOT NULL,
  recipient_user_id BINARY(16) NOT NULL,
  type VARCHAR(64) NOT NULL,
  title VARCHAR(128) NOT NULL,
  content VARCHAR(512) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  read_at TIMESTAMP(6) NULL DEFAULT NULL,
  PRIMARY KEY (id),
  INDEX idx_notification_recipient_created (recipient_user_id, created_at, id),
  INDEX idx_notification_recipient_unread (recipient_user_id, read_at),
  CONSTRAINT fk_notification_recipient
    FOREIGN KEY (recipient_user_id) REFERENCES sys_user(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
