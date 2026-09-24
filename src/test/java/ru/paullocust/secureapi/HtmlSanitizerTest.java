package ru.paullocust.secureapi;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import ru.paullocust.secureapi.util.HtmlSanitizer;

import static org.assertj.core.api.Assertions.assertThat;

/** Модульные тесты защиты от XSS. */
class HtmlSanitizerTest {

    private final HtmlSanitizer sanitizer = new HtmlSanitizer();

    @ParameterizedTest(name = "payload вырезается: {0}")
    @ValueSource(strings = {
            "<script>alert('xss')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\"></iframe>",
            "<body onload=alert('xss')>"
    })
    @DisplayName("Активная разметка удаляется полностью")
    void removesActiveMarkup(String payload) {
        String sanitized = sanitizer.sanitize(payload);

        assertThat(sanitized).doesNotContain("<script", "<img", "<svg", "<iframe", "onerror", "onload");
    }

    @Test
    @DisplayName("Обычный текст сохраняется, теги форматирования снимаются")
    void keepsPlainText() {
        assertThat(sanitizer.sanitize("Привет, <b>мир</b>!")).isEqualTo("Привет, мир!");
        assertThat(sanitizer.sanitize("  Просто текст  ")).isEqualTo("Просто текст");
    }

    @Test
    @DisplayName("Экранирование на выходе превращает спецсимволы в HTML-сущности")
    void encodesSpecialCharacters() {
        String encoded = sanitizer.encodeForHtml("Tom & Jerry <3 \"quotes\"");

        assertThat(encoded).contains("&amp;").contains("&lt;");
        assertThat(encoded).doesNotContain(" < ");
    }

    @Test
    @DisplayName("null обрабатывается без исключений")
    void handlesNull() {
        assertThat(sanitizer.sanitize(null)).isNull();
        assertThat(sanitizer.encodeForHtml(null)).isNull();
    }
}
