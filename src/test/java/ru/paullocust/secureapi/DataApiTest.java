package ru.paullocust.secureapi;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Проверки защищённых эндпоинтов данных и разграничения доступа (OWASP A01). */
class DataApiTest extends AbstractApiTest {

    @Test
    @DisplayName("GET /api/data без токена возвращает 401")
    void dataIsClosedWithoutToken() throws Exception {
        mockMvc.perform(get("/api/data"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("unauthorized"));
    }

    @Test
    @DisplayName("GET /api/data с валидным токеном возвращает данные")
    void dataIsAvailableWithToken() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items").isArray())
                .andExpect(jsonPath("$.totalItems").value(greaterThanOrEqualTo(3)));
    }

    @Test
    @DisplayName("GET /api/me возвращает профиль владельца токена")
    void meReturnsProfileOfTokenOwner() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value(USER_USERNAME))
                .andExpect(jsonPath("$.role").value("USER"));
    }

    @Test
    @DisplayName("POST /api/data создаёт запись от имени владельца токена")
    void createPost() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);
        String payload = """
                {"title":"Заметка о безопасности","content":"Параметризованные запросы и хеширование паролей."}
                """;

        mockMvc.perform(post("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.author").value(USER_USERNAME));
    }

    @Test
    @DisplayName("Слишком короткий заголовок отклоняется валидацией")
    void createPostValidatesInput() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);
        String payload = """
                {"title":"a","content":""}
                """;

        mockMvc.perform(post("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("validation_error"));
    }

    @Test
    @DisplayName("Чужую запись удалить нельзя: 403 (Broken Access Control)")
    void cannotDeleteForeignPost() throws Exception {
        String ownerToken = loginAndGetToken(USER_USERNAME, USER_PASSWORD);
        long postId = createPost(ownerToken, "Запись Алисы", "Текст, который может удалить только автор.");

        String register = """
                {"username":"mallory.tester","password":"Mallory#2026pw"}
                """;
        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(register))
                .andExpect(status().isCreated());

        String intruderToken = loginAndGetToken("mallory.tester", "Mallory#2026pw");

        mockMvc.perform(delete("/api/data/" + postId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(intruderToken)))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("forbidden"));
    }

    @Test
    @DisplayName("Автор удаляет свою запись: 204")
    void ownerCanDeleteOwnPost() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);
        long postId = createPost(token, "Временная запись", "Будет удалена автором.");

        mockMvc.perform(delete("/api/data/" + postId)
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("GET /api/users доступен администратору")
    void adminSeesUserList() throws Exception {
        String adminToken = loginAndGetToken(ADMIN_USERNAME, ADMIN_PASSWORD);

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(adminToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].username").isNotEmpty())
                .andExpect(jsonPath("$[0].passwordHash").doesNotExist());
    }

    @Test
    @DisplayName("GET /api/users запрещён обычному пользователю: 403")
    void regularUserCannotSeeUserList() throws Exception {
        String userToken = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(userToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Пропущенный обязательный параметр даёт 400, а не 500")
    void missingRequiredParameterIsBadRequest() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/data/search")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("bad_request"));
    }

    @Test
    @DisplayName("Параметр не того типа даёт 400, а не 500")
    void wrongParameterTypeIsBadRequest() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/data").param("page", "abc")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isBadRequest());

        mockMvc.perform(delete("/api/data/abc")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Неподдерживаемый HTTP-метод даёт 405 с заголовком Allow")
    void unsupportedMethodIsNotAllowed() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(put("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(header().exists(HttpHeaders.ALLOW))
                .andExpect(jsonPath("$.error").value("method_not_allowed"));
    }

    @Test
    @DisplayName("Тело не в формате JSON даёт 415")
    void unsupportedMediaTypeIsRejected() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(post("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.TEXT_PLAIN)
                        .content("title=test"))
                .andExpect(status().isUnsupportedMediaType())
                .andExpect(jsonPath("$.error").value("unsupported_media_type"));
    }

    private long createPost(String token, String title, String content) throws Exception {
        String payload = objectMapper.writeValueAsString(new PostPayload(title, content));
        String response = mockMvc.perform(post("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);

        JsonNode json = objectMapper.readTree(response);
        return json.get("id").asLong();
    }

    private record PostPayload(String title, String content) {
    }
}
