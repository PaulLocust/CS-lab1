package ru.paullocust.secureapi.domain;

/** Роли пользователей. */
public enum Role {

    /** Читает данные и создаёт свои записи. */
    USER,

    /** Видит список пользователей и может удалять любые записи. */
    ADMIN;

    /** Имя authority для Spring Security: {@code ROLE_USER}, {@code ROLE_ADMIN}. */
    public String authority() {
        return "ROLE_" + name();
    }
}
