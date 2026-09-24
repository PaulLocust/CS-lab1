package ru.paullocust.secureapi.exception;

/** Запрошенный ресурс не найден (HTTP 404). */
public class ResourceNotFoundException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public ResourceNotFoundException(String message) {
        super(message);
    }
}
