package ru.paullocust.secureapi.exception;

/** Логин уже занят (HTTP 409). */
public class UsernameAlreadyTakenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UsernameAlreadyTakenException() {
        super("Пользователь с таким логином уже существует");
    }
}
