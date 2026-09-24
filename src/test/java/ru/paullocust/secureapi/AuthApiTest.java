package ru.paullocust.secureapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Проверки эндпоинтов аутентификации (OWASP A07). */
class AuthApiTest extends AbstractApiTest {

    @Test
    @DisplayName("POST /auth/login с верными данными выдаёт JWT")
    void loginReturnsToken() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload(USER_USERNAME, USER_PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.username").value(USER_USERNAME))
                .andExpect(jsonPath("$.roles[0]").value("ROLE_USER"))
                .andExpect(jsonPath("$.expiresInSeconds").value(greaterThan(0)));
    }

    @Test
    @DisplayName("POST /auth/login с неверным паролем возвращает 401 без деталей")
    void loginWithWrongPasswordIsRejected() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload(USER_USERNAME, "WrongPassword#1")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_credentials"))
                // ответ не должен подсказывать, существует ли пользователь
                .andExpect(content().string(not(containsString("не найден"))));
    }

    @Test
    @DisplayName("Несуществующий пользователь получает тот же ответ, что и неверный пароль")
    void unknownUserGetsSameResponse() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload("no.such.user", "WrongPassword#1")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid_credentials"))
                .andExpect(jsonPath("$.message").value("Неверный логин или пароль"));
    }

    @Test
    @DisplayName("Пустой логин отсекается валидацией (400), до БД запрос не доходит")
    void validationRejectsEmptyUsername() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload("", "SomePassword#1")))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("validation_error"))
                .andExpect(jsonPath("$.fieldErrors.username").isNotEmpty());
    }

    @Test
    @DisplayName("Серия неудачных попыток включает блокировку 429 с Retry-After")
    void bruteForceIsThrottled() throws Exception {
        String target = "brute.target";

        // max-login-attempts=3 в тестовом профиле
        for (int attempt = 0; attempt < 3; attempt++) {
            mockMvc.perform(post("/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(loginPayload(target, "WrongPassword#" + attempt)))
                    .andExpect(status().isUnauthorized());
        }

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload(target, "WrongPassword#4")))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.error").value("too_many_attempts"));
    }

    @Test
    @DisplayName("POST /auth/register создаёт пользователя и не возвращает хеш пароля")
    void registerCreatesUser() throws Exception {
        String payload = """
                {"username":"new.tester","password":"NewTester#2026pw"}
                """;

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("new.tester"))
                .andExpect(jsonPath("$.role").value("USER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    @DisplayName("Слабый пароль при регистрации отклоняется парольной политикой")
    void registerRejectsWeakPassword() throws Exception {
        String payload = """
                {"username":"weak.tester","password":"password"}
                """;

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fieldErrors.password").isNotEmpty());
    }
}
