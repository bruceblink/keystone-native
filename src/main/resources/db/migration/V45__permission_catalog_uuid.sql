-- 一次性重建权限目录：权限 ID 使用固定 UUIDv5，关联列使用 BINARY(16)。
-- 本迁移允许破坏性更新。旧权限主键、旧角色权限关系和菜单权限字符串不再作为授权来源。
-- 权限目录与 Keystone Phoenix PermissionCatalog 保持同一 71 项两段权限集合。
DROP TABLE IF EXISTS sys_menu_permission;
DROP TABLE IF EXISTS sys_role_permission;
DROP TABLE IF EXISTS sys_permission;

CREATE TABLE sys_permission (
  id BINARY(16) NOT NULL,
  code VARCHAR(128) NOT NULL,
  name VARCHAR(128) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uk_permission_code (code)
);

CREATE TABLE sys_role_permission (
  role_id BIGINT NOT NULL,
  permission_id BINARY(16) NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES sys_role(id) ON DELETE CASCADE,
  CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES sys_permission(id) ON DELETE CASCADE
);

-- 菜单与权限使用独立关联表；旧菜单权限字段仅保留展示用途，不参与授权。
CREATE TABLE sys_menu_permission (
  menu_id BIGINT NOT NULL,
  permission_id BINARY(16) NOT NULL,
  PRIMARY KEY (menu_id, permission_id),
  CONSTRAINT fk_menu_permission_menu FOREIGN KEY (menu_id) REFERENCES sys_menu(id) ON DELETE CASCADE,
  CONSTRAINT fk_menu_permission_permission FOREIGN KEY (permission_id) REFERENCES sys_permission(id) ON DELETE CASCADE
);

INSERT INTO sys_permission (id, code, name) VALUES
  (UUID_TO_BIN('ea639614-06da-53ea-b354-e71c95820e88', 0), 'api-key:create', 'api-key / create'),
  (UUID_TO_BIN('5884953b-0a5d-5138-92eb-5ecea20ee2dd', 0), 'api-key:read', 'api-key / read'),
  (UUID_TO_BIN('9f584388-c1be-5b82-b4dd-b8d2a26aa680', 0), 'api-key:revoke', 'api-key / revoke'),
  (UUID_TO_BIN('39218549-9c89-59e1-8901-53d4516598b4', 0), 'api-key:rotate', 'api-key / rotate'),
  (UUID_TO_BIN('413fdc5f-23e8-57d6-a17e-c566088cb2ea', 0), 'audit:delete', 'audit / delete'),
  (UUID_TO_BIN('2f3b8330-ab31-51c7-aea5-57ad1cb4196f', 0), 'audit:export', 'audit / export'),
  (UUID_TO_BIN('d5bba25f-b90d-5629-874d-e7444ecfe859', 0), 'audit:read', 'audit / read'),
  (UUID_TO_BIN('b78d5b74-f8c9-5896-9aff-35ae189afb71', 0), 'cache:refresh', 'cache / refresh'),
  (UUID_TO_BIN('15f3f6e1-ff4f-54a7-997a-db0b87b7843f', 0), 'config:create', 'config / create'),
  (UUID_TO_BIN('6b535fec-5df1-5ed4-b677-5b51919cec16', 0), 'config:read', 'config / read'),
  (UUID_TO_BIN('17fafb30-0cff-5f84-8195-8bf00c355770', 0), 'config:refresh', 'config / refresh'),
  (UUID_TO_BIN('d8de5edc-7064-5482-a987-d09f503a8339', 0), 'config:update', 'config / update'),
  (UUID_TO_BIN('60e36c0e-50f4-5515-984e-6f0e0f1d13fd', 0), 'department:create', 'department / create'),
  (UUID_TO_BIN('5ba6174e-728a-5570-af02-c62d1cd93262', 0), 'department:delete', 'department / delete'),
  (UUID_TO_BIN('44b3b7b0-e903-5625-874f-cca38e8a7cf5', 0), 'department:read', 'department / read'),
  (UUID_TO_BIN('b761a223-b788-55e4-b9d1-089b43875d2e', 0), 'department:update', 'department / update'),
  (UUID_TO_BIN('fd6908e8-553a-51f0-a7e2-459e93d6a92c', 0), 'dictionary:create', 'dictionary / create'),
  (UUID_TO_BIN('5f82fa3f-2df4-5d5e-9dfd-68f8e2cc1d43', 0), 'dictionary:delete', 'dictionary / delete'),
  (UUID_TO_BIN('b14fc2e5-e8a2-542f-b84d-a6000cf9502b', 0), 'dictionary:read', 'dictionary / read'),
  (UUID_TO_BIN('ff49cfba-08a4-5ff3-b8c6-cde9bcc390da', 0), 'dictionary:refresh', 'dictionary / refresh'),
  (UUID_TO_BIN('954edbae-d6f2-5656-9e00-ad594cbd75ca', 0), 'dictionary:update', 'dictionary / update'),
  (UUID_TO_BIN('a5340abb-bec5-5215-81de-ad573717c3b6', 0), 'file:read', 'file / read'),
  (UUID_TO_BIN('cffad4c8-70e1-5424-9a44-215541284174', 0), 'file:write', 'file / write'),
  (UUID_TO_BIN('79d34de8-44c6-552c-a200-912bb777904d', 0), 'job:create', 'job / create'),
  (UUID_TO_BIN('21625f88-f29e-5a65-ac45-f38fce4d1345', 0), 'job:delete', 'job / delete'),
  (UUID_TO_BIN('e5f26fcb-91d7-5d69-892d-792382c7b4d8', 0), 'job:read', 'job / read'),
  (UUID_TO_BIN('adb7d11f-1ffb-5af0-9c05-ef78f4d18373', 0), 'job:run', 'job / run'),
  (UUID_TO_BIN('88c0bffd-b470-54d2-b8a9-ca87ce9197c1', 0), 'job:update', 'job / update'),
  (UUID_TO_BIN('2a20bc5b-577a-5104-ba69-2ba3757caaed', 0), 'job:update-status', 'job / update-status'),
  (UUID_TO_BIN('e2ffbb61-a8f1-5dae-bbbe-c1b280fded52', 0), 'login-log:delete', 'login-log / delete'),
  (UUID_TO_BIN('c9a5f217-4caf-58ab-8575-517b7948eb31', 0), 'login-log:export', 'login-log / export'),
  (UUID_TO_BIN('28794ce4-7545-5182-86b2-fa8c81b9d73d', 0), 'login-log:read', 'login-log / read'),
  (UUID_TO_BIN('2594dd1b-5b8b-567d-ad2b-53034fb1d20a', 0), 'menu:create', 'menu / create'),
  (UUID_TO_BIN('f3339043-491d-56a7-8d35-0f1c1ff9145c', 0), 'menu:delete', 'menu / delete'),
  (UUID_TO_BIN('7d0afc38-3ac1-5598-8cb0-56ce1e3e9cad', 0), 'menu:manage', 'menu / manage'),
  (UUID_TO_BIN('6e92e842-f0cf-5361-a9a2-7091e9f97a6e', 0), 'menu:read', 'menu / read'),
  (UUID_TO_BIN('ed8a349b-4ac5-5020-905d-2e2d9f6256bc', 0), 'menu:update', 'menu / update'),
  (UUID_TO_BIN('76c9d2a5-1669-5f62-abb2-a21b57488c3b', 0), 'mfa:manage', 'mfa / manage'),
  (UUID_TO_BIN('d2cf4c74-2316-5198-8256-7474d60d79e2', 0), 'notice:create', 'notice / create'),
  (UUID_TO_BIN('c93dc0ba-3704-5aa7-b507-fb844fd20a97', 0), 'notice:delete', 'notice / delete'),
  (UUID_TO_BIN('ecd64243-75c7-5ddb-925d-5274414b4ac3', 0), 'notice:read', 'notice / read'),
  (UUID_TO_BIN('25863a1c-0bb4-56da-8a8f-0a220bfb9efc', 0), 'notice:update', 'notice / update'),
  (UUID_TO_BIN('6ec88be9-b7cb-55ca-b133-f2553729024d', 0), 'online-session:read', 'online-session / read'),
  (UUID_TO_BIN('1860c80c-f586-533e-a2ba-aad6f84ae705', 0), 'online-session:revoke', 'online-session / revoke'),
  (UUID_TO_BIN('9b766cb3-b182-5df0-bb7c-c29dc9acb72f', 0), 'operation-log:delete', 'operation-log / delete'),
  (UUID_TO_BIN('66145f47-f4c2-5e26-9815-e9cfb6c3ec45', 0), 'operation-log:export', 'operation-log / export'),
  (UUID_TO_BIN('eefabbce-9b0f-532e-b1f6-cbf5be79bd17', 0), 'operation-log:read', 'operation-log / read'),
  (UUID_TO_BIN('aefe330b-d46a-5950-85eb-3e40145a379d', 0), 'permission:manage', 'permission / manage'),
  (UUID_TO_BIN('9b0e3d97-957b-5396-8383-f115d877f335', 0), 'permission:read', 'permission / read'),
  (UUID_TO_BIN('70ee9bb6-1cc9-5e2f-986b-299b2518b637', 0), 'post:create', 'post / create'),
  (UUID_TO_BIN('63fe2b0a-2691-5533-aaac-4c0bc355181f', 0), 'post:delete', 'post / delete'),
  (UUID_TO_BIN('1da2fcb1-d1de-5dc9-a8bc-1b83224a7963', 0), 'post:export', 'post / export'),
  (UUID_TO_BIN('732cebd4-52ff-5e93-bad9-8c2c27965748', 0), 'post:read', 'post / read'),
  (UUID_TO_BIN('12193e27-834b-5cec-8b3b-f44778fda668', 0), 'post:update', 'post / update'),
  (UUID_TO_BIN('57ac1b2e-c51d-5fbd-a054-cc5814fa84b5', 0), 'role:assign', 'role / assign'),
  (UUID_TO_BIN('ea2f15d2-bc73-5fa7-88d9-f46edc36a2fa', 0), 'role:create', 'role / create'),
  (UUID_TO_BIN('3b172563-11a5-5285-b5f1-380de90f10e3', 0), 'role:delete', 'role / delete'),
  (UUID_TO_BIN('e5e9c4ab-3b01-5a2e-adc1-52687406f951', 0), 'role:export', 'role / export'),
  (UUID_TO_BIN('cde4f45a-7f3d-53e2-8b17-65700a7b1169', 0), 'role:manage', 'role / manage'),
  (UUID_TO_BIN('d8611c63-e243-5b86-ae92-37518cdafacb', 0), 'role:read', 'role / read'),
  (UUID_TO_BIN('c3a455ea-21a1-5631-a9e9-cac811a1d647', 0), 'role:update', 'role / update'),
  (UUID_TO_BIN('53b5cc2a-bc5f-5ae1-a739-5fe0f130184b', 0), 'server:read', 'server / read'),
  (UUID_TO_BIN('35fcad46-81fd-5210-ab56-2968550ee869', 0), 'session:read', 'session / read'),
  (UUID_TO_BIN('d0169f94-52df-568e-8273-19bd20042f23', 0), 'session:revoke', 'session / revoke'),
  (UUID_TO_BIN('1efa0dd9-49fe-5dcf-9ee0-7c8a97cba2a7', 0), 'user:create', 'user / create'),
  (UUID_TO_BIN('422c7409-3b0e-572b-86cb-0d2aa02cff8f', 0), 'user:delete', 'user / delete'),
  (UUID_TO_BIN('29253819-a8ca-5339-aaab-4931d6c3db54', 0), 'user:export', 'user / export'),
  (UUID_TO_BIN('a9ad29a4-b827-539e-a12a-6ad3ac323196', 0), 'user:import', 'user / import'),
  (UUID_TO_BIN('950c8856-7230-5a63-937f-472185c3a8c4', 0), 'user:read', 'user / read'),
  (UUID_TO_BIN('55819f35-2dcb-55c0-9f8a-828eee3225dc', 0), 'user:reset-password', 'user / reset-password'),
  (UUID_TO_BIN('86a67646-6b4b-54c3-8e30-06d515a463d6', 0), 'user:update', 'user / update');

-- ADMIN 使用完整目录；角色代码使用 V3 建立的大小写约定。
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
CROSS JOIN sys_permission p
WHERE r.code = 'ADMIN';

-- USER 保留普通用户的业务访问边界，并使用 canonical session:revoke 完成当前会话退出。
INSERT IGNORE INTO sys_role_permission (role_id, permission_id)
SELECT r.id, p.id
FROM sys_role r
CROSS JOIN sys_permission p
WHERE r.code = 'USER'
  AND p.code IN (
    'user:read',
    'user:update',
    'session:revoke',
    'department:read',
    'dictionary:read',
    'post:read',
    'menu:read',
    'file:read',
    'file:write'
  );
