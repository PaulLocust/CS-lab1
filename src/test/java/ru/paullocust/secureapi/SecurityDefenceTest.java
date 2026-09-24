package ru.paullocust.secureapi;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import ru.paullocust.secureapi.config.JwtProperties;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Проверки конкретных мер защиты: XSS, SQL-инъекции, целостность JWT, security-заголовки.
 */
class SecurityDefenceTest extends AbstractApiTest {

    @Autowired
    private JwtProperties jwtProperties;

    // ------------------------------------------------------------------ XSS

    @Test
    @DisplayName("XSS: HTML-разметка вырезается при сохранении и экранируется при выдаче")
    void xssPayloadIsNeutralized() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);
        String payload = """
                {"title":"XSS <script>alert('pwned')</script>",
                 "content":"Ссылка <a href=\\"javascript:alert(1)\\">клик</a> и картинка <img src=x onerror=alert(2)> & текст"}
                """;

        String created = mockMvc.perform(post("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.title").value(not(containsString("<script"))))
                .andExpect(jsonPath("$.content").value(not(containsString("<img"))))
                .andExpect(jsonPath("$.content").value(not(containsString("onerror"))))
                .andExpect(jsonPath("$.content").value(not(containsString("javascript:"))))
                .andReturn()
                .getResponse()
                .getContentAsString(StandardCharsets.UTF_8);

        // Спецсимволы отдаются в HTML-сущностях (экранирование на выходе)
        assertThat(created).contains("&amp;");

        // И в общем списке данные тоже приходят безопасными
        mockMvc.perform(get("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(content().string(not(containsString("<script"))))
                .andExpect(content().string(not(containsString("onerror="))));
    }

    // ----------------------------------------------------------------- SQLi

    @Test
    @DisplayName("SQLi: классический payload ' OR '1'='1 трактуется как обычный текст")
    void sqlInjectionInSearchIsHarmless() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/data/search")
                        .param("query", "' OR '1'='1")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$.length()").value(0));
    }

    @Test
    @DisplayName("SQLi: попытка DROP TABLE не разрушает данные")
    void sqlInjectionCannotDropTable() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/data/search")
                        .param("query", "x'; DROP TABLE posts; --")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk());

        // таблица на месте, данные доступны
        mockMvc.perform(get("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items").isArray());
    }

    @Test
    @DisplayName("SQLi в логине не даёт обойти аутентификацию")
    void sqlInjectionInLoginIsRejected() throws Exception {
        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload("admin'--", "anything123")))
                .andExpect(status().isBadRequest());

        mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginPayload("admin", "' OR 1=1 --")))
                .andExpect(status().isUnauthorized());
    }

    // ------------------------------------------------------------------ JWT

    @Test
    @DisplayName("JWT: мусор вместо токена отклоняется")
    void garbageTokenIsRejected() throws Exception {
        mockMvc.perform(get("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer("not.a.valid.token")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT: подделанная подпись отклоняется")
    void tamperedSignatureIsRejected() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);
        String tampered = token.substring(0, token.length() - 2) + (token.endsWith("A") ? "BB" : "AA");

        mockMvc.perform(get("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(tampered)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT: токен, подписанный чужим ключом, отклоняется (даже с ролью ADMIN)")
    void foreignKeyTokenIsRejected() throws Exception {
        String foreignToken = Jwts.builder()
                .subject(USER_USERNAME)
                .issuer(jwtProperties.issuer())
                .audience().add(jwtProperties.audience()).and()
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(600)))
                .claim("roles", List.of("ROLE_ADMIN"))
                .signWith(Keys.hmacShaKeyFor(
                        "attacker-secret-attacker-secret-attacker-secret".getBytes(StandardCharsets.UTF_8)),
                        Jwts.SIG.HS256)
                .compact();

        mockMvc.perform(get("/api/users")
                        .header(HttpHeaders.AUTHORIZATION, bearer(foreignToken)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("JWT: просроченный токен отклоняется")
    void expiredTokenIsRejected() throws Exception {
        Instant past = Instant.now().minusSeconds(3600);
        String expiredToken = Jwts.builder()
                .subject(USER_USERNAME)
                .issuer(jwtProperties.issuer())
                .audience().add(jwtProperties.audience()).and()
                .issuedAt(Date.from(past))
                .expiration(Date.from(past.plusSeconds(60)))
                .claim("roles", List.of("ROLE_USER"))
                .signWith(Keys.hmacShaKeyFor(jwtProperties.secret().getBytes(StandardCharsets.UTF_8)),
                        Jwts.SIG.HS256)
                .compact();

        mockMvc.perform(get("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(expiredToken)))
                .andExpect(status().isUnauthorized());
    }

    // -------------------------------------------------------------- Headers

    @Test
    @DisplayName("Ответы содержат защитные HTTP-заголовки")
    void securityHeadersArePresent() throws Exception {
        String token = loginAndGetToken(USER_USERNAME, USER_PASSWORD);

        mockMvc.perform(get("/api/data")
                        .header(HttpHeaders.AUTHORIZATION, bearer(token)))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(header().string("X-Frame-Options", "DENY"))
                .andExpect(header().string("Content-Security-Policy", containsString("default-src 'none'")))
                .andExpect(header().string("Referrer-Policy", "no-referrer"));
    }

    @Test
    @DisplayName("Неизвестный путь закрыт по умолчанию (deny by default)")
    void unknownPathIsDeniedByDefault() throws Exception {
        mockMvc.perform(get("/internal/secrets"))
                .andExpect(status().isUnauthorized());
    }
}
