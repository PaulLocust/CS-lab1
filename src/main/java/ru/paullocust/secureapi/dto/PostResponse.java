package ru.paullocust.secureapi.dto;

import java.time.Instant;

/** Запись в ответах API; строковые поля уже экранированы. */
public record PostResponse(
        Long id,
        String title,
        String content,
        String author,
        Instant createdAt
) {
}
