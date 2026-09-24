package ru.paullocust.secureapi.util;

/**
 * Готовит пользовательские данные к записи в лог. Перевод строки в логине или URL иначе
 * позволяет «дорисовать» в журнале поддельную запись (log injection).
 */
public final class LogSanitizer {

    /** Для коротких идентификаторов: логин, имя ресурса. */
    private static final int DEFAULT_MAX_LENGTH = 64;

    /** Для сообщений об ошибках и путей запроса. */
    public static final int MESSAGE_MAX_LENGTH = 256;

    private LogSanitizer() {
        // utility class
    }

    /** Убирает управляющие символы (включая CR/LF) и обрезает длину. */
    public static String forLog(String value) {
        return forLog(value, DEFAULT_MAX_LENGTH);
    }

    /** То же с явным ограничением длины. */
    public static String forLog(String value, int maxLength) {
        if (value == null) {
            return "null";
        }
        String truncated = value.length() > maxLength ? value.substring(0, maxLength) + "..." : value;
        StringBuilder sanitized = new StringBuilder(truncated.length());
        for (int i = 0; i < truncated.length(); i++) {
            char symbol = truncated.charAt(i);
            sanitized.append(Character.isISOControl(symbol) ? '_' : symbol);
        }
        return sanitized.toString();
    }
}
