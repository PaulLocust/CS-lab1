package ru.paullocust.secureapi.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

/**
 * Настройки безопасности ({@code app.security.*}).
 *
 * @param maxLoginAttempts  сколько неудачных попыток входа до блокировки
 * @param loginLockDuration на сколько блокируется вход
 * @param allowedOrigins    разрешённые источники для CORS
 */
@Validated
@ConfigurationProperties(prefix = "app.security")
public record SecurityProperties(

        @Min(1)
        int maxLoginAttempts,

        @NotNull
        Duration loginLockDuration,

        @NotNull
        List<String> allowedOrigins
) {

    /** Копия списка: настройки не должны меняться извне после старта. */
    public SecurityProperties {
        allowedOrigins = allowedOrigins == null ? List.of() : List.copyOf(allowedOrigins);
    }
}
