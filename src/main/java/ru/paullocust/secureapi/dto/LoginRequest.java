package ru.paullocust.secureapi.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Тело запроса {@code POST /auth/login}. Логин ограничен безопасным алфавитом и длиной. */
public record LoginRequest(

        @NotBlank(message = "Логин обязателен")
        @Size(min = 3, max = 64, message = "Длина логина: 3–64 символа")
        @Pattern(regexp = "^[A-Za-z0-9._-]+$", message = "Допустимы латиница, цифры и символы . _ -")
        String username,

        @NotBlank(message = "Пароль обязателен")
        @Size(min = 8, max = 128, message = "Длина пароля: 8–128 символов")
        String password
) {

    /** Без пароля — чтобы не попал в логи. */
    @Override
    public String toString() {
        return "LoginRequest{username='" + username + "'}";
    }
}
