package ru.paullocust.secureapi.util;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Entities;
import org.jsoup.parser.Parser;
import org.jsoup.safety.Safelist;
import org.owasp.encoder.Encode;
import org.springframework.stereotype.Component;

/**
 * Защита от XSS в два слоя: {@link #sanitize(String)} вырезает разметку перед записью в БД,
 * {@link #encodeForHtml(String)} экранирует спецсимволы перед отдачей клиенту.
 */
@Component
public class HtmlSanitizer {

    private static final Safelist NO_HTML_ALLOWED = Safelist.none();

    private static final Document.OutputSettings OUTPUT_SETTINGS = new Document.OutputSettings()
            .prettyPrint(false)
            .escapeMode(Entities.EscapeMode.xhtml);

    /** Убирает теги и атрибуты, оставляя чистый текст. */
    public String sanitize(String raw) {
        if (raw == null) {
            return null;
        }
        String withoutMarkup = Jsoup.clean(raw, "", NO_HTML_ALLOWED, OUTPUT_SETTINGS);
        // Jsoup заменяет спецсимволы на сущности — разворачиваем обратно,
        // чтобы в БД лежал текст, а не смесь текста и HTML-сущностей.
        return Parser.unescapeEntities(withoutMarkup, false).trim();
    }

    /** Экранирует значение для безопасной вставки в HTML. */
    public String encodeForHtml(String value) {
        return value == null ? null : Encode.forHtml(value);
    }
}
