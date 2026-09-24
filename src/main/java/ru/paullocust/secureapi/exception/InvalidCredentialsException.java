package ru.paullocust.secureapi.exception;

/** Неверный логин или пароль — сообщение одинаковое для обоих случаев. */
public class InvalidCredentialsException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InvalidCredentialsException() {
        super("Неверный логин или пароль");
    }
}
