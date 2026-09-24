package ru.paullocust.secureapi;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import ru.paullocust.secureapi.config.JwtProperties;
import ru.paullocust.secureapi.security.JwtService;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Модульные тесты выпуска и проверки JWT. */
class JwtServiceTest {

    private static final JwtProperties PROPERTIES = new JwtProperties(
            "unit-test-secret-unit-test-secret-unit-test",
            "cs-lab1-secure-api",
            "cs-lab1-clients",
            Duration.ofMinutes(15));

    private final JwtService jwtService = new JwtService(PROPERTIES);

    private static UserDetails user() {
        return User.withUsername("alice")
                .password("{noop}irrelevant")
                .authorities("ROLE_USER")
                .build();
    }

    @Test
    @DisplayName("Выпущенный токен проходит проверку и содержит субъект и роли")
    void issuedTokenIsValid() {
        String token = jwtService.issueToken(user());

        Jws<Claims> parsed = jwtService.parse(token);
        Claims claims = parsed.getPayload();

        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getIssuer()).isEqualTo("cs-lab1-secure-api");
        assertThat(claims.getAudience()).contains("cs-lab1-clients");
        assertThat(claims.getExpiration()).isAfter(claims.getIssuedAt());
        assertThat(jwtService.extractRoles(claims)).containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("В payload токена нет пароля пользователя")
    void tokenDoesNotLeakPassword() {
        String token = jwtService.issueToken(user());

        assertThat(token).doesNotContain("irrelevant");
    }

    @Test
    @DisplayName("Изменённый payload ломает подпись")
    void tamperedTokenIsRejected() {
        String token = jwtService.issueToken(user());
        String[] parts = token.split("\\.");
        String tampered = parts[0] + '.' + parts[1] + ".AAAA" + parts[2].substring(4);

        assertThatThrownBy(() -> jwtService.parse(tampered)).isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Токен другого издателя не принимается")
    void foreignIssuerIsRejected() {
        JwtProperties foreignProperties = new JwtProperties(
                PROPERTIES.secret(), "other-issuer", PROPERTIES.audience(), Duration.ofMinutes(15));
        String foreignToken = new JwtService(foreignProperties).issueToken(user());

        assertThatThrownBy(() -> jwtService.parse(foreignToken)).isInstanceOf(JwtException.class);
    }

    @Test
    @DisplayName("Слишком короткий секрет не даёт запустить сервис")
    void shortSecretIsRejected() {
        JwtProperties weak = new JwtProperties("short-secret", "iss", "aud", Duration.ofMinutes(5));

        assertThatThrownBy(() -> new JwtService(weak))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("256");
    }
}
