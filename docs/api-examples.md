# Примеры вызовов API

Ниже — реальный вывод прогона [`scripts/smoke-test.sh`](../scripts/smoke-test.sh) против локально
запущенного приложения (`java -jar target/secure-api-1.0.0.jar`). Значения `id`, времени и токенов
у вас будут другими.

Получение токена в переменную:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice#Str0ng-2026"}' \
  | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)
```

---

## 1. Health check

```bash
curl http://localhost:8080/actuator/health
```

```json
{"status":"UP"}
```

## 2. POST /auth/login — успешная аутентификация

```bash
curl -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"Alice#Str0ng-2026"}'
```

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiI5MGJlZTFkZC04ODA5LTRiNmMtODljZi02NmQzZWUwN2IwMzAiLCJzdWIiOiJhbGljZSIsImlzcyI6ImNzLWxhYjEtc2VjdXJlLWFwaSIsImF1ZCI6WyJjcy1sYWIxLWNsaWVudHMiXSwiaWF0IjoxNzg5MDU5MDM4LCJuYmYiOjE3ODkwNTkwMzgsImV4cCI6MTc4OTA1OTkzOCwicm9sZXMiOlsiUk9MRV9VU0VSIl19.0HuZcIkkqrABbghVuHv3XF0Z9VyzvJ7YL4wraFQs2-w",
  "tokenType": "Bearer",
  "expiresInSeconds": 900,
  "username": "alice",
  "roles": ["ROLE_USER"]
}
```

Декодированный payload токена (вторая часть, Base64URL):

```json
{
  "jti": "90bee1dd-8809-4b6c-89cf-66d3ee07b030",
  "sub": "alice",
  "iss": "cs-lab1-secure-api",
  "aud": ["cs-lab1-clients"],
  "iat": 1789059038,
  "nbf": 1789059038,
  "exp": 1789059938,
  "roles": ["ROLE_USER"]
}
```

## 3. POST /auth/login — неверный пароль

```bash
curl -i -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"WrongPassword#1"}'
```

```
HTTP/1.1 401
```
```json
{
  "timestamp": "2026-09-10T16:50:39.412Z",
  "status": 401,
  "error": "invalid_credentials",
  "message": "Неверный логин или пароль",
  "path": "/auth/login"
}
```

Тот же самый ответ приходит и для несуществующего логина — по ответу нельзя понять,
зарегистрирован пользователь или нет.

## 4. GET /api/data без токена → 401

```bash
curl http://localhost:8080/api/data
```

```json
{
  "timestamp": "2026-09-10T16:50:39.531770300Z",
  "status": 401,
  "error": "unauthorized",
  "message": "Требуется действительный access-токен: заголовок 'Authorization: Bearer <token>'",
  "path": "/api/data"
}
```

## 5. GET /api/data с токеном → 200

```bash
curl "http://localhost:8080/api/data?page=0&size=3" -H "Authorization: Bearer $TOKEN"
```

```json
{
  "items": [
    {
      "id": 1,
      "title": "OWASP Top 10 2021",
      "content": "A01 Broken Access Control, A03 Injection и A07 Identification and Authentication Failures разбираются в этой лабораторной работе.",
      "author": "admin",
      "createdAt": "2026-09-10T16:53:41.593659Z"
    },
    {
      "id": 2,
      "title": "Параметризованные запросы",
      "content": "PreparedStatement передаёт данные отдельно от текста SQL, поэтому кавычка в поиске остаётся обычным символом.",
      "author": "admin",
      "createdAt": "2026-09-10T16:53:41.593659Z"
    },
    {
      "id": 3,
      "title": "Зачем нужен BCrypt",
      "content": "Медленная функция с солью и настраиваемой стоимостью защищает базу паролей от перебора по радужным таблицам.",
      "author": "alice",
      "createdAt": "2026-09-10T16:53:41.593659Z"
    }
  ],
  "page": 0,
  "size": 3,
  "totalItems": 3,
  "totalPages": 1
}
```

## 6. GET /api/me — профиль владельца токена

```bash
curl http://localhost:8080/api/me -H "Authorization: Bearer $TOKEN"
```

```json
{"id":2,"username":"alice","role":"USER","enabled":true,"createdAt":"2026-09-10T16:50:33.555537Z"}
```

Хеш пароля наружу не отдаётся.

## 7. POST /api/data — XSS-payload нейтрализуется

```bash
curl -X POST http://localhost:8080/api/data \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"XSS <script>alert(1)</script>","content":"<img src=x onerror=alert(2)> plain text & symbols"}'
```

```json
{
  "id": 5,
  "title": "XSS",
  "content": "text and &amp; symbol",
  "author": "alice",
  "createdAt": "2026-09-10T16:50:55.722616200Z"
}
```

То же самое с кириллицей (через `scripts/smoke-test.ps1`):

```json
{
  "id": 4,
  "title": "XSS  Проверка",
  "content": "Обычный текст &amp; спецсимволы",
  "author": "alice",
  "createdAt": "2026-09-10T16:53:42.841624600Z"
}
```

Теги `<script>` и `<img onerror=...>` удалены при сохранении, `&` возвращён как HTML-сущность.

## 8. SQL-инъекция в поиске

```bash
curl -G http://localhost:8080/api/data/search \
  --data-urlencode "query=' OR '1'='1" \
  -H "Authorization: Bearer $TOKEN"
```

```json
[]
```

```bash
curl -G http://localhost:8080/api/data/search \
  --data-urlencode "query=x'; DROP TABLE posts; --" \
  -H "Authorization: Bearer $TOKEN"
```

```
HTTP 200 — пустой результат; таблица не пострадала:
GET /api/data по-прежнему возвращает записи (HTTP 200)
```

Инъекция в поле логина отсекается ещё валидацией:

```bash
curl -i -X POST http://localhost:8080/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin'--\",\"password\":\"anything123\"}"
```

```
HTTP/1.1 400
{"status":400,"error":"validation_error","message":"Запрос не прошёл валидацию",
 "fieldErrors":{"username":"Допустимы латиница, цифры и символы . _ -"}}
```

## 9. Разграничение прав

```bash
# обычный пользователь пытается получить список учётных записей
curl -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/users -H "Authorization: Bearer $TOKEN"
# 403

# администратор — успешно
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin#Str0ng-2026"}' | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)
curl -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/users -H "Authorization: Bearer $ADMIN_TOKEN"
# 200
```

Удаление чужой записи:

```
DELETE /api/data/7  (запись создана alice, токен другого пользователя)
HTTP 403 {"error":"forbidden","message":"Недостаточно прав для выполнения операции"}
```

## 10. Подделанный токен → 401

```bash
curl -o /dev/null -w '%{http_code}\n' http://localhost:8080/api/data \
  -H "Authorization: Bearer ${TOKEN%??}AA"
# 401
```

## 11. Защитные HTTP-заголовки

```bash
curl -D - -o /dev/null http://localhost:8080/api/data -H "Authorization: Bearer $TOKEN"
```

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()
```

`Strict-Transport-Security` добавляется при обращении по HTTPS.

## 12. Защита от перебора паролей

```
попытка 1 -> HTTP 401
попытка 2 -> HTTP 401
попытка 3 -> HTTP 401
попытка 4 -> HTTP 401
попытка 5 -> HTTP 401
попытка 6 -> HTTP 429   (заголовок Retry-After: 900)
```
