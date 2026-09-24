package ru.paullocust.secureapi.exception;

import java.time.Duration;

/** Превышен лимит неудачных попыток входа: временная блокировка (HTTP 429). */
public class TooManyAttemptsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final long retryAfterSeconds;

    public TooManyAttemptsException(Duration retryAfter) {
        super("Слишком много неудачных попыток входа, повторите позже");
        this.retryAfterSeconds = Math.max(1L, retryAfter.toSeconds());
    }

    /** Значение для заголовка {@code Retry-After}. */
    public long getRetryAfterSeconds() {
        return retryAfterSeconds;
    }
}
