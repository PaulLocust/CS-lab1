package ru.paullocust.secureapi.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/**
 * Параметры выпуска JWT ({@code app.jwt.*}).
 *
 * @param secret         ключ подписи HS256, не короче 32 символов
 * @param issuer         claim {@code iss}
 * @param audience       claim {@code aud}
 * @param accessTokenTtl время жизни токена
 */
@Validated
@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(

        @NotBlank
        @Size(min = 32, message = "app.jwt.secret должен быть не короче 32 символов (256 бит для HS256)")
        String secret,

        @NotBlank
        String issuer,

        @NotBlank
        String audience,

        @NotNull
        Duration accessTokenTtl
) {
}
