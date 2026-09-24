package ru.paullocust.secureapi.config;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/** Демонстрационные учётные записи ({@code app.seed.*}); пароли приходят из конфигурации. */
@Validated
@ConfigurationProperties(prefix = "app.seed")
public record SeedProperties(

        @NotBlank String adminUsername,
        @NotBlank String adminPassword,
        @NotBlank String userUsername,
        @NotBlank String userPassword
) {
}
