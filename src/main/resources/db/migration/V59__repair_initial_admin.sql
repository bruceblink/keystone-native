-- V46 重建身份表时恢复了旧管理员哈希，并丢失首次改密标记。
-- 仅修复从未登录、从未改密且仍保留原始哈希的启用账号；其他账号保持原样。
UPDATE sys_user
SET password_hash = '$2a$12$kjxM5Gygcre909f4.loS7uO7NiAf56RAqjQnTQnK5rlACdFf.N3/W',
    must_change_password = TRUE,
    credential_version = credential_version + 1
WHERE id = UUID_TO_BIN('5faed4bb-63af-5158-bd3c-1200c539cfd9', 0)
  AND username = 'admin'
  AND BINARY password_hash = BINARY '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy'
  AND enabled = TRUE
  AND must_change_password = FALSE
  AND last_password_changed_at IS NULL
  AND login_at IS NULL;
