package ru.paullocust.secureapi.dto;

import org.springframework.data.domain.Page;

import java.util.List;
import java.util.function.Function;

/**
 * Постраничный ответ; размер страницы ограничен контроллером.
 *
 * @param items      элементы страницы
 * @param page       номер страницы, с нуля
 * @param size       размер страницы
 * @param totalItems всего элементов
 * @param totalPages всего страниц
 */
public record PageResponse<T>(
        List<T> items,
        int page,
        int size,
        long totalItems,
        int totalPages
) {

    public static <S, T> PageResponse<T> from(Page<S> page, Function<S, T> mapper) {
        return new PageResponse<>(
                page.getContent().stream().map(mapper).toList(),
                page.getNumber(),
                page.getSize(),
                page.getTotalElements(),
                page.getTotalPages());
    }
}
