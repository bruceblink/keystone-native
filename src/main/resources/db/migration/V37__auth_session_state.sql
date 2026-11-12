-- 独立保存会话状态，刷新令牌表只保存令牌轮换明细。
CREATE TABLE IF NOT EXISTS sys_auth_session (
  id CHAR(36) PRIMARY KEY,
  user_id BIGINT NOT NULL,
  client_id VARCHAR(128) NOT NULL,
  refresh_family_id CHAR(36) NOT NULL,
  refresh_expires_at TIMESTAMP NOT NULL,
  idle_expires_at TIMESTAMP NOT NULL,
  last_seen_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_auth_session_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
  INDEX idx_auth_session_user_state (user_id, revoked_at),
  INDEX idx_auth_session_family (refresh_family_id),
  INDEX idx_auth_session_expiry (refresh_expires_at, idle_expires_at, revoked_at)
);

-- 迁移已经存在的令牌族；同一会话保留仍有效的最后状态。
INSERT IGNORE INTO sys_auth_session(id, user_id, client_id, refresh_family_id, refresh_expires_at, idle_expires_at, last_seen_at, revoked_at)
SELECT session_id,
       user_id,
       COALESCE(MAX(client_id), 'web'),
       refresh_family_id,
       MAX(expires_at),
       MAX(COALESCE(idle_expires_at, expires_at)),
       MAX(created_at),
       CASE WHEN SUM(revoked_at IS NULL) > 0 THEN NULL ELSE MAX(revoked_at) END
FROM sys_refresh_token
WHERE session_id IS NOT NULL AND refresh_family_id IS NOT NULL
GROUP BY session_id, user_id, refresh_family_id;
