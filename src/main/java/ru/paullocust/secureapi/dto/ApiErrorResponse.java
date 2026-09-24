package ru.paullocust.secureapi.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.Map;

/**
 * Формат ошибки API: наружу только код и общая формулировка, без стектрейсов и деталей БД.
 *
 * @param timestamp   момент ошибки (UTC)
 * @param status      HTTP-код
 * @param error       машинночитаемое обозначение
 * @param message     описание без внутренних деталей
 * @param path        запрошенный путь
 * @param fieldErrors ошибки валидации по полям
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiErrorResponse(
        Instant timestamp,
        int status,
        String error,
        String message,
        String path,
        Map<String, String> fieldErrors
) {

    public static ApiErrorResponse of(int status, String error, String message, String path) {
        return new ApiErrorResponse(Instant.now(), status, error, message, path, null);
    }
}
