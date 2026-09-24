package ru.paullocust.secureapi.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Тело запроса {@code POST /api/data}. Длина полей ограничена, содержимое чистится от HTML. */
public record CreatePostRequest(

        @NotBlank(message = "Заголовок обязателен")
        @Size(min = 3, max = 120, message = "Длина заголовка: 3–120 символов")
        String title,

        @NotBlank(message = "Текст записи обязателен")
        @Size(min = 1, max = 5000, message = "Длина текста: 1–5000 символов")
        String content
) {
}
