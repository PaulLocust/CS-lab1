package ru.paullocust.secureapi.dto;

import java.util.List;

/**
 * Ответ на успешный вход.
 *
 * @param accessToken      JWT для заголовка Authorization
 * @param tokenType        всегда {@code Bearer}
 * @param expiresInSeconds сколько секунд токен действителен
 * @param username         имя пользователя
 * @param roles            выданные роли
 */
public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresInSeconds,
        String username,
        List<String> roles
) {

    public static LoginResponse bearer(String token, long expiresInSeconds, String username, List<String> roles) {
        return new LoginResponse(token, "Bearer", expiresInSeconds, username, List.copyOf(roles));
    }
}
