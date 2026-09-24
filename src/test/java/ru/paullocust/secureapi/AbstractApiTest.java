package ru.paullocust.secureapi;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import ru.paullocust.secureapi.security.LoginAttemptService;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Базовый класс интеграционных тестов: поднимает контекст приложения
 * и даёт хелперы для получения JWT.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
abstract class AbstractApiTest {

    protected static final String ADMIN_USERNAME = "admin";
    protected static final String ADMIN_PASSWORD = "Admin#Test-2026";
    protected static final String USER_USERNAME = "alice";
    protected static final String USER_PASSWORD = "Alice#Test-2026";
    protected static final String LOCALHOST = "127.0.0.1";

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    protected ObjectMapper objectMapper;

    @Autowired
    protected LoginAttemptService loginAttemptService;

    /** Счётчик неудачных попыток общий на контекст — сбрасываем, чтобы тесты не влияли друг на друга. */
    @BeforeEach
    void resetLoginAttempts() {
        for (String username : List.of(ADMIN_USERNAME, USER_USERNAME)) {
            loginAttemptService.reset(loginAttemptService.key(username, LOCALHOST));
        }
    }

    protected String loginAndGetToken(String username, String password) throws Exception {
        String responseBody = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload(username, password)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);

        return objectMapper.readTree(responseBody).get("accessToken").asText();
    }

    protected String loginPayload(String username, String password) throws Exception {
        return objectMapper.writeValueAsString(new LoginPayload(username, password));
    }

    protected static String bearer(String token) {
        return "Bearer " + token;
    }

    /** Простая структура для сериализации тела запроса логина в тестах. */
    protected record LoginPayload(String username, String password) {
    }
}
