INSERT INTO sys_user (username, password_hash, display_name)
SELECT 'admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'Administrator'
WHERE NOT EXISTS (SELECT 1 FROM sys_user WHERE username = 'admin');
