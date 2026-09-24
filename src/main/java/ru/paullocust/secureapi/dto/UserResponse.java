package ru.paullocust.secureapi.dto;

import java.time.Instant;

/** Профиль пользователя; хеша пароля здесь нет. */
public record UserResponse(
        Long id,
        String username,
        String role,
        boolean enabled,
        Instant createdAt
) {
}
