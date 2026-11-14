#!/usr/bin/env bash

# 在隔离的 MySQL 8.4 数据库中验证 V56 的完整执行、重复执行和部分执行恢复。
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

MYSQL_PORT=${NATIVE_V56_MYSQL_PORT:-3307}
APP_PORT=${NATIVE_V56_APP_PORT:-18080}
PROJECT="keystone-native-v56-${BASHPID:-$$}"
TEMP_ROOT=$(mktemp -d -t keystone-native-v56)
COMPOSE_FILE="$TEMP_ROOT/compose.yml"
APP_LOG="$TEMP_ROOT/app.log"
MYSQL_CONTAINER="${PROJECT}-mysql-1"
APP_PID=""

# 清理只属于本次验证的进程、容器、网络和临时文件。
cleanup() {
  if [[ -n "$APP_PID" ]] && kill -0 "$APP_PID" 2>/dev/null; then
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
  fi

  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
  rm -rf "$TEMP_ROOT"
}

trap cleanup EXIT

cat > "$COMPOSE_FILE" <<COMPOSE
services:
  mysql:
    image: mysql:8.4
    environment:
      MYSQL_DATABASE: keystone
      MYSQL_USER: keystone
      MYSQL_PASSWORD: keystone
      MYSQL_ROOT_PASSWORD: root
    ports:
      - "${MYSQL_PORT}:3306"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-ukeystone", "-pkeystone"]
      interval: 2s
      timeout: 3s
      retries: 30
COMPOSE

docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d mysql >/dev/null

health_status="starting"
for _attempt in $(seq 1 60); do
  health_status=$(docker inspect --format '{{.State.Health.Status}}' "$MYSQL_CONTAINER" 2>/dev/null || true)
  [[ "$health_status" == "healthy" ]] && break
  sleep 2
done

if [[ "$health_status" != "healthy" ]]; then
  docker compose -p "$PROJECT" -f "$COMPOSE_FILE" logs --no-color mysql >&2
  echo "V56 verification MySQL did not become healthy" >&2
  exit 1
fi

./gradlew quarkusBuild -x test --no-daemon >"$TEMP_ROOT/build.log" 2>&1 || {
  cat "$TEMP_ROOT/build.log" >&2
  exit 1
}

# 使用测试密钥启动独立应用，让 Flyway 在空库中真实执行全部迁移。
DB_URL="jdbc:mysql://127.0.0.1:${MYSQL_PORT}/keystone" \
DB_USERNAME=keystone \
DB_PASSWORD=keystone \
JWT_PRIVATE_KEY_LOCATION=src/test/resources/keys/privateKey.pem \
JWT_PUBLIC_KEY_LOCATION=src/test/resources/keys/publicKey.pem \
JWT_VERIFY_PUBLIC_KEY_LOCATION=src/test/resources/keys/publicKey.pem \
JWT_KEY_ID=v56-verification \
HTTP_REQUIRE_HTTPS=false \
HTTP_HSTS_ENABLED=false \
WEBAUTHN_ENABLED=false \
MFA_MASTER_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= \
MFA_RECOVERY_PEPPER=v56-verification \
TRUSTED_PROXY_CIDRS=127.0.0.1/32 \
QUARKUS_HTTP_PORT="$APP_PORT" \
java -jar build/quarkus-app/quarkus-run.jar >"$APP_LOG" 2>&1 &
APP_PID=$!

ready=false
for _attempt in $(seq 1 60); do
  if curl --fail --silent "http://127.0.0.1:${APP_PORT}/api/q/health/ready" >/dev/null 2>&1; then
    ready=true
    break
  fi

  if ! kill -0 "$APP_PID" 2>/dev/null; then
    cat "$APP_LOG" >&2
    echo "V56 verification application stopped before readiness" >&2
    exit 1
  fi

  sleep 2
done

if [[ "$ready" != true ]]; then
  cat "$APP_LOG" >&2
  echo "V56 verification application did not become ready" >&2
  exit 1
fi

mysql_query() {
  docker exec -e MYSQL_PWD=keystone "$MYSQL_CONTAINER" \
    mysql -h localhost -ukeystone -Dkeystone --batch --skip-column-names -e "$1"
}

run_v56() {
  docker exec -i -e MYSQL_PWD=keystone "$MYSQL_CONTAINER" \
    mysql -h localhost -ukeystone -Dkeystone < src/main/resources/db/migration/V56__owner_scope_resources.sql >/dev/null
}

assert_count() {
  local label=$1
  local expected=$2
  local query=$3
  local actual
  actual=$(mysql_query "$query")

  if [[ "$actual" != "$expected" ]]; then
    echo "$label: expected $expected, got $actual" >&2
    exit 1
  fi
}

assert_v56_shape() {
  assert_count "schema version" 1 \
    "SELECT COUNT(*) FROM flyway_schema_history WHERE version='56' AND success=1"
  assert_count "notice owner column" 1 \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='sys_notice' AND column_name='owner_id' AND column_type='binary(16)'"
  assert_count "job creator column" 1 \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='sys_job' AND column_name='created_by' AND column_type='binary(16)'"
  assert_count "notice owner index" 3 \
    "SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='sys_notice' AND index_name='idx_notice_owner_time'"
  assert_count "notice owner index columns" 1 \
    "SELECT COUNT(*) FROM (SELECT index_name, GROUP_CONCAT(column_name ORDER BY seq_in_index) AS index_columns FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='sys_notice' AND index_name='idx_notice_owner_time' GROUP BY index_name HAVING index_columns='owner_id,created_at,id') AS indexes"
  assert_count "job creator index" 2 \
    "SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='sys_job' AND index_name='idx_job_created_by'"
  assert_count "job creator index columns" 1 \
    "SELECT COUNT(*) FROM (SELECT index_name, GROUP_CONCAT(column_name ORDER BY seq_in_index) AS index_columns FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='sys_job' AND index_name='idx_job_created_by' GROUP BY index_name HAVING index_columns='created_by,id') AS indexes"
  assert_count "notice owner foreign key" 1 \
    "SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_schema=DATABASE() AND table_name='sys_notice' AND constraint_name='fk_notice_owner'"
  assert_count "notice owner foreign key target" 1 \
    "SELECT COUNT(*) FROM information_schema.referential_constraints AS rc JOIN information_schema.key_column_usage AS kcu ON kcu.constraint_schema=rc.constraint_schema AND kcu.constraint_name=rc.constraint_name AND kcu.table_name=rc.table_name WHERE rc.constraint_schema=DATABASE() AND rc.table_name='sys_notice' AND rc.constraint_name='fk_notice_owner' AND rc.delete_rule='SET NULL' AND kcu.column_name='owner_id' AND kcu.referenced_table_name='sys_user'"
  assert_count "job creator foreign key" 1 \
    "SELECT COUNT(*) FROM information_schema.table_constraints WHERE table_schema=DATABASE() AND table_name='sys_job' AND constraint_name='fk_job_created_by'"
  assert_count "job creator foreign key target" 1 \
    "SELECT COUNT(*) FROM information_schema.referential_constraints AS rc JOIN information_schema.key_column_usage AS kcu ON kcu.constraint_schema=rc.constraint_schema AND kcu.constraint_name=rc.constraint_name AND kcu.table_name=rc.table_name WHERE rc.constraint_schema=DATABASE() AND rc.table_name='sys_job' AND rc.constraint_name='fk_job_created_by' AND rc.delete_rule='SET NULL' AND kcu.column_name='created_by' AND kcu.referenced_table_name='sys_user'"
}

# 应用启动已证明 V56 可以在空库中首次执行，先核对最终结构。
assert_v56_shape

# 完整结构重跑必须不新增重复列、索引或外键。
run_v56
assert_v56_shape

# 删除索引和外键，模拟前一次执行在字段之后中断，重跑必须恢复缺失对象。
mysql_query "ALTER TABLE sys_notice DROP FOREIGN KEY fk_notice_owner, DROP INDEX idx_notice_owner_time; ALTER TABLE sys_job DROP FOREIGN KEY fk_job_created_by, DROP INDEX idx_job_created_by;"
run_v56
assert_v56_shape

# 删除字段及其依赖对象，模拟字段变更完成前中断，重跑必须恢复完整结构。
mysql_query "ALTER TABLE sys_notice DROP FOREIGN KEY fk_notice_owner, DROP INDEX idx_notice_owner_time, DROP COLUMN owner_id; ALTER TABLE sys_job DROP FOREIGN KEY fk_job_created_by, DROP INDEX idx_job_created_by, DROP COLUMN created_by;"
run_v56
assert_v56_shape

echo "V56 migration verification passed: fresh, replay, index/fk partial, and column partial"
