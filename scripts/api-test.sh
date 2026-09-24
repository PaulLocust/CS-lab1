#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Функциональная проверка всех эндпоинтов API с проверкой кодов ответа.
#
# Запуск:  bash scripts/api-test.sh [http://localhost:8080]
# Код возврата: 0 — все проверки прошли, 1 — есть провалы.
#
# Отличие от smoke-test.sh: там показываются атаки (SQLi, XSS, перебор паролей),
# здесь — что каждый эндпоинт отвечает тем, чем должен, включая коды ошибок.
#
# Тела запросов записаны латиницей: в Git Bash на Windows аргументы curl
# перекодируются в системную кодировку и кириллица внутри -d ломает JSON.
# ---------------------------------------------------------------------------
set -u

BASE_URL="${1:-http://localhost:8080}"
ADMIN_USER="${APP_SEED_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${APP_SEED_ADMIN_PASSWORD:-Admin#Str0ng-2026}"
USER_USER="${APP_SEED_USER_USERNAME:-alice}"
USER_PASS="${APP_SEED_USER_PASSWORD:-Alice#Str0ng-2026}"

PASSED=0
FAILED=0
BODY_FILE="$(mktemp)"
trap 'rm -f "$BODY_FILE"' EXIT

if [ -t 1 ]; then
  GREEN=$'\033[32m'; RED=$'\033[31m'; BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  GREEN=''; RED=''; BOLD=''; DIM=''; RESET=''
fi

section() { printf '\n%s== %s%s\n' "$BOLD" "$1" "$RESET"; }
ok()      { PASSED=$((PASSED + 1)); printf '  %sOK%s   %s\n' "$GREEN" "$RESET" "$1"; }
bad()     { FAILED=$((FAILED + 1)); printf '  %sFAIL%s %s\n' "$RED" "$RESET" "$1"; }
note()    { printf '       %s%s%s\n' "$DIM" "$1" "$RESET"; }

# api <METHOD> <PATH> [TOKEN] [JSON-BODY] -> HTTP_CODE, HTTP_BODY
api() {
  local method="$1" path="$2" token="${3:-}" body="${4:-}"
  local args=(-s -o "$BODY_FILE" -w '%{http_code}' -X "$method" "$BASE_URL$path")
  [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' -d "$body")
  HTTP_CODE="$(curl "${args[@]}")"
  HTTP_BODY="$(cat "$BODY_FILE")"
}

expect_code() {
  local title="$1" want="$2"
  if [ "$HTTP_CODE" = "$want" ]; then
    ok "$title -> HTTP $HTTP_CODE"
  else
    bad "$title -> ожидался HTTP $want, получен $HTTP_CODE"
    note "тело: $(printf '%s' "$HTTP_BODY" | head -c 160)"
  fi
}

expect_contains() {
  local title="$1" needle="$2"
  case "$HTTP_BODY" in
    *"$needle"*) ok "$title: в ответе есть '$needle'" ;;
    *)           bad "$title: в ответе нет '$needle'"
                 note "тело: $(printf '%s' "$HTTP_BODY" | head -c 160)" ;;
  esac
}

expect_lacks() {
  local title="$1" needle="$2"
  case "$HTTP_BODY" in
    *"$needle"*) bad "$title: в ответе найдено '$needle', а не должно быть"
                 note "тело: $(printf '%s' "$HTTP_BODY" | head -c 160)" ;;
    *)           ok "$title: '$needle' в ответе отсутствует" ;;
  esac
}

json_value() { printf '%s' "$1" | grep -o "\"$2\":\"[^\"]*\"" | head -1 | cut -d'"' -f4; }
json_number() { printf '%s' "$1" | grep -o "\"$2\":[0-9]*" | head -1 | cut -d':' -f2; }

login() {  # login <user> <pass> -> печатает токен
  local resp
  resp="$(curl -s -X POST "$BASE_URL/auth/login" -H 'Content-Type: application/json' \
          -d "{\"username\":\"$1\",\"password\":\"$2\"}")"
  json_value "$resp" accessToken
}

# --------------------------------------------------------------- подготовка
printf '%sПроверка API: %s%s\n' "$BOLD" "$BASE_URL" "$RESET"

api GET /actuator/health
if [ "$HTTP_CODE" != "200" ]; then
  printf '\n%sПриложение недоступно на %s (HTTP %s).%s\n' "$RED" "$BASE_URL" "$HTTP_CODE" "$RESET"
  printf 'Запустите его командой:  java -jar target/secure-api-1.0.0.jar\n'
  exit 1
fi

STAMP="$(date +%s)"
NEW_USER="tester.$STAMP"
NEW_PASS="Tester#2026pass"
OTHER_USER="mallory.$STAMP"
OTHER_PASS="Mallory#2026pass"

# ------------------------------------------------------- 1. health и docs
section "1. Служебные эндпоинты"
api GET /actuator/health
expect_code "GET /actuator/health" 200
expect_contains "GET /actuator/health" '"status":"UP"'

api GET /v3/api-docs
expect_code "GET /v3/api-docs (описание OpenAPI)" 200

# ------------------------------------------------------- 2. регистрация
section "2. POST /auth/register"
api POST /auth/register "" "{\"username\":\"$NEW_USER\",\"password\":\"$NEW_PASS\"}"
expect_code "регистрация нового пользователя" 201
expect_contains "регистрация" '"role":"USER"'
expect_lacks "регистрация" 'passwordHash'

api POST /auth/register "" "{\"username\":\"$NEW_USER\",\"password\":\"$NEW_PASS\"}"
expect_code "повторная регистрация того же логина" 409

api POST /auth/register "" "{\"username\":\"weak.$STAMP\",\"password\":\"password\"}"
expect_code "слабый пароль отклонён парольной политикой" 400

api POST /auth/register "" "{\"username\":\"bad user!\",\"password\":\"Tester#2026pass\"}"
expect_code "логин с недопустимыми символами отклонён" 400

# ------------------------------------------------------- 3. аутентификация
section "3. POST /auth/login"
api POST /auth/login "" "{\"username\":\"$USER_USER\",\"password\":\"$USER_PASS\"}"
expect_code "вход с верными данными" 200
expect_contains "вход" '"tokenType":"Bearer"'
TOKEN="$(json_value "$HTTP_BODY" accessToken)"
if [ -n "$TOKEN" ]; then ok "токен получен (${#TOKEN} символов)"; else bad "токен не получен"; fi

api POST /auth/login "" "{\"username\":\"$USER_USER\",\"password\":\"WrongPassword#1\"}"
expect_code "неверный пароль" 401
expect_contains "неверный пароль" '"error":"invalid_credentials"'

api POST /auth/login "" "{\"username\":\"no.such.user\",\"password\":\"WrongPassword#1\"}"
expect_code "несуществующий пользователь" 401
expect_contains "ответ не раскрывает существование учётки" '"error":"invalid_credentials"'

api POST /auth/login "" "{\"username\":\"admin'--\",\"password\":\"anything123\"}"
expect_code "SQL-payload в логине отсекается валидацией" 400

api POST /auth/login "" '{"username":"alice"}'
expect_code "запрос без поля password" 400

# успешный вход сбрасывает счётчик неудачных попыток
TOKEN="$(login "$USER_USER" "$USER_PASS")"
ADMIN_TOKEN="$(login "$ADMIN_USER" "$ADMIN_PASS")"
if [ -n "$ADMIN_TOKEN" ]; then ok "токен администратора получен"; else bad "токен администратора не получен"; fi

# ------------------------------------------------------- 4. GET /api/data
section "4. GET /api/data"
api GET /api/data
expect_code "без токена" 401
expect_contains "без токена" '"error":"unauthorized"'

api GET /api/data "$TOKEN"
expect_code "с токеном" 200
expect_contains "с токеном" '"items"'

api "GET" "/api/data?page=0&size=2" "$TOKEN"
expect_code "с пагинацией page=0&size=2" 200
expect_contains "пагинация" '"size":2'

api "GET" "/api/data?size=999" "$TOKEN"
expect_code "size сверх лимита отклоняется" 400

api GET /api/data "Bearer-мусор"
expect_code "мусор вместо токена" 401

TAMPERED="${TOKEN%??}AA"
api GET /api/data "$TAMPERED"
expect_code "подделанная подпись токена" 401

# ------------------------------------------------- 5. GET /api/data/search
section "5. GET /api/data/search"
api "GET" "/api/data/search?query=BCrypt" "$TOKEN"
expect_code "поиск по существующему слову" 200

api "GET" "/api/data/search?query=%27%20OR%20%271%27%3D%271" "$TOKEN"
expect_code "SQL-инъекция в параметре поиска" 200
expect_contains "инъекция трактуется как текст" '[]'

api "GET" "/api/data/search" "$TOKEN"
expect_code "поиск без обязательного параметра" 400

# ------------------------------------------------------ 6. POST /api/data
section "6. POST /api/data"
api POST /api/data "$TOKEN" '{"title":"Functional test note","content":"Created by api-test.sh"}'
expect_code "создание записи" 201
expect_contains "автор берётся из токена" "\"author\":\"$USER_USER\""
POST_ID="$(json_number "$HTTP_BODY" id)"
if [ -n "$POST_ID" ]; then ok "запись создана, id=$POST_ID"; else bad "id созданной записи не получен"; fi

api POST /api/data "" '{"title":"No token","content":"should fail"}'
expect_code "создание без токена" 401

api POST /api/data "$TOKEN" '{"title":"a","content":""}'
expect_code "слишком короткий заголовок" 400
expect_contains "валидация" '"error":"validation_error"'

api POST /api/data "$TOKEN" '{"title":"XSS <script>alert(1)</script>","content":"<img src=x onerror=alert(2)> text & symbols"}'
expect_code "создание записи с XSS-payload" 201
expect_lacks "разметка вырезана" '<script'
expect_lacks "обработчик события вырезан" 'onerror'
expect_contains "спецсимвол экранирован" '&amp;'
XSS_ID="$(json_number "$HTTP_BODY" id)"

# ---------------------------------------------------------- 7. GET /api/me
section "7. GET /api/me"
api GET /api/me "$TOKEN"
expect_code "профиль владельца токена" 200
expect_contains "профиль" "\"username\":\"$USER_USER\""
expect_lacks "профиль не отдаёт хеш пароля" 'passwordHash'

api GET /api/me
expect_code "без токена" 401

# ------------------------------------------------------- 8. GET /api/users
section "8. GET /api/users"
api GET /api/users "$TOKEN"
expect_code "обычный пользователь" 403
expect_contains "обычный пользователь" '"error":"forbidden"'

api GET /api/users "$ADMIN_TOKEN"
expect_code "администратор" 200
expect_lacks "список не содержит хешей паролей" '$2b$'

# ------------------------------------------------ 9. DELETE /api/data/{id}
section "9. DELETE /api/data/{id}"
api POST /auth/register "" "{\"username\":\"$OTHER_USER\",\"password\":\"$OTHER_PASS\"}"
expect_code "регистрация второго пользователя" 201
OTHER_TOKEN="$(login "$OTHER_USER" "$OTHER_PASS")"

api DELETE "/api/data/$POST_ID" "$OTHER_TOKEN"
expect_code "удаление чужой записи запрещено" 403

api DELETE "/api/data/$POST_ID" "$TOKEN"
expect_code "автор удаляет свою запись" 204

api DELETE "/api/data/$POST_ID" "$TOKEN"
expect_code "повторное удаление той же записи" 404

api DELETE "/api/data/$XSS_ID" "$ADMIN_TOKEN"
expect_code "администратор удаляет чужую запись" 204

api DELETE "/api/data/0" "$TOKEN"
expect_code "некорректный id" 400

# ------------------------------------------------- 10. прочие проверки
section "10. Общие правила доступа"
api GET /internal/secrets
expect_code "неизвестный путь закрыт по умолчанию" 401

api PUT /api/data "$TOKEN" '{"title":"wrong method","content":"x"}'
expect_code "неподдерживаемый HTTP-метод" 405

HTTP_CODE="$(curl -s -o "$BODY_FILE" -w '%{http_code}' -X POST "$BASE_URL/api/data"      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: text/plain' -d 'title=test')"
HTTP_BODY="$(cat "$BODY_FILE")"
expect_code "тело не в формате JSON" 415

printf '\n%sЗащитные заголовки ответа:%s\n' "$BOLD" "$RESET"
curl -s -D - -o /dev/null "$BASE_URL/api/data" -H "Authorization: Bearer $TOKEN" \
  | grep -Ei 'content-security-policy|x-content-type-options|x-frame-options|referrer-policy|permissions-policy' \
  | sed 's/^/  /'

# ------------------------------------------------------------------ итог
printf '\n%s================================%s\n' "$BOLD" "$RESET"
printf '%sПройдено: %s%d%s   Провалено: %s%d%s\n' \
  "$BOLD" "$GREEN" "$PASSED" "$RESET" "$RED" "$FAILED" "$RESET"

if [ "$FAILED" -gt 0 ]; then
  printf '%sЕсть проваленные проверки.%s\n' "$RED" "$RESET"
  exit 1
fi
printf '%sВсе проверки пройдены.%s\n' "$GREEN" "$RESET"
printf '%sЗащита от перебора паролей проверяется отдельно: bash scripts/smoke-test.sh%s\n' "$DIM" "$RESET"
