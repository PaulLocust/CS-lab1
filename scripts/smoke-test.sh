#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Ручная проверка API через curl: аутентификация, доступ к данным,
# защита от XSS и SQL-инъекций, разграничение прав.
#
# Запуск:  bash scripts/smoke-test.sh [http://localhost:8080]
#
# Примечание: тела запросов записаны латиницей сознательно — в Git Bash на Windows
# аргументы curl перекодируются в системную кодировку, и кириллица внутри -d ломает
# JSON ещё до отправки. Кириллицу само API принимает нормально: это проверяют
# автотесты и PowerShell-версия скрипта (scripts/smoke-test.ps1).
# ---------------------------------------------------------------------------
set -u

BASE_URL="${1:-http://localhost:8080}"
ADMIN_USER="admin"
ADMIN_PASS="${APP_SEED_ADMIN_PASSWORD:-Admin#Str0ng-2026}"
USER_USER="alice"
USER_PASS="${APP_SEED_USER_PASSWORD:-Alice#Str0ng-2026}"

section() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
show()    { printf '  %s\n' "$1"; }

token_of() {
  local username="$1" password="$2"
  curl -s -X POST "$BASE_URL/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"$username\",\"password\":\"$password\"}" \
    | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4
}

section "1. Health check"
curl -s "$BASE_URL/actuator/health"; echo

section "2. POST /auth/login — успешная аутентификация"
curl -s -X POST "$BASE_URL/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER_USER\",\"password\":\"$USER_PASS\"}"; echo

TOKEN="$(token_of "$USER_USER" "$USER_PASS")"
show "получен токен длиной ${#TOKEN} символов"

section "3. POST /auth/login — неверный пароль (ожидаем 401)"
curl -s -o /dev/null -w '  HTTP %{http_code}\n' -X POST "$BASE_URL/auth/login" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USER_USER\",\"password\":\"WrongPassword#1\"}"

section "4. GET /api/data без токена (ожидаем 401)"
curl -s -w '\n  HTTP %{http_code}\n' "$BASE_URL/api/data"

section "5. GET /api/data с токеном (ожидаем 200)"
curl -s -w '\n  HTTP %{http_code}\n' "$BASE_URL/api/data?page=0&size=3" \
  -H "Authorization: Bearer $TOKEN"

section "6. GET /api/me — профиль владельца токена"
curl -s -w '\n  HTTP %{http_code}\n' "$BASE_URL/api/me" -H "Authorization: Bearer $TOKEN"

section "7. POST /api/data с XSS-payload (разметка должна быть вырезана)"
curl -s -w '\n  HTTP %{http_code}\n' -X POST "$BASE_URL/api/data" \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"title":"XSS <script>alert(1)</script>","content":"<img src=x onerror=alert(2)> plain text & symbols"}'

section "8. GET /api/data/search с SQL-инъекцией (данные не утекают, таблица цела)"
curl -s -w '\n  HTTP %{http_code}\n' -G "$BASE_URL/api/data/search" \
  --data-urlencode "query=' OR '1'='1" \
  -H "Authorization: Bearer $TOKEN"
show "и попытка DROP TABLE:"
curl -s -o /dev/null -w '  HTTP %{http_code}\n' -G "$BASE_URL/api/data/search" \
  --data-urlencode "query=x'; DROP TABLE posts; --" \
  -H "Authorization: Bearer $TOKEN"

section "9. GET /api/users обычным пользователем (ожидаем 403)"
curl -s -o /dev/null -w '  HTTP %{http_code}\n' "$BASE_URL/api/users" -H "Authorization: Bearer $TOKEN"

section "10. GET /api/users администратором (ожидаем 200)"
ADMIN_TOKEN="$(token_of "$ADMIN_USER" "$ADMIN_PASS")"
curl -s -o /dev/null -w '  HTTP %{http_code}\n' "$BASE_URL/api/users" -H "Authorization: Bearer $ADMIN_TOKEN"

section "11. Подделанный токен (ожидаем 401)"
curl -s -o /dev/null -w '  HTTP %{http_code}\n' "$BASE_URL/api/data" \
  -H "Authorization: Bearer ${TOKEN%??}AA"

section "12. Защитные HTTP-заголовки"
curl -s -D - -o /dev/null "$BASE_URL/api/data" -H "Authorization: Bearer $TOKEN" \
  | grep -Ei 'content-security-policy|x-content-type-options|x-frame-options|referrer-policy|permissions-policy'

section "13. Brute-force: 6 неудачных попыток подряд (ожидаем 429 в конце)"
for i in 1 2 3 4 5 6; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE_URL/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"brute.target\",\"password\":\"WrongPassword#$i\"}")
  show "попытка $i -> HTTP $code"
done

printf '\nГотово.\n'
