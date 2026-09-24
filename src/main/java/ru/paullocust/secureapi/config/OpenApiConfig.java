package ru.paullocust.secureapi.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/**
 * Описание API для Swagger UI ({@code /swagger-ui.html}). Схема {@code bearer-jwt}
 * позволяет подставить токен прямо в интерфейсе.
 */
@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "CS-lab1 Secure REST API",
                version = "1.0.0",
                description = "Учебный защищённый REST API: JWT-аутентификация, BCrypt, "
                        + "защита от SQL-инъекций и XSS, CI/CD с SAST/SCA-сканерами"))
@SecurityScheme(
        name = "bearer-jwt",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        in = SecuritySchemeIn.HEADER)
public class OpenApiConfig {
}
