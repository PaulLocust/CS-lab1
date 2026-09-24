package ru.paullocust.secureapi.repository;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

/**
 * Поиск по записям на «сыром» JDBC. Текст запроса — константа, пользовательский ввод
 * уходит только значениями параметров {@code ?}, так что SQL-кодом он стать не может.
 */
@Repository
public class PostJdbcRepository {

    private static final String SEARCH_SQL = """
            SELECT id, title, content, author_username, created_at
              FROM posts
             WHERE LOWER(title) LIKE LOWER(?) ESCAPE '\\'
                OR LOWER(content) LIKE LOWER(?) ESCAPE '\\'
             ORDER BY created_at DESC
             LIMIT ?
            """;

    private static final RowMapper<PostRow> ROW_MAPPER = (rs, rowNum) -> {
        Timestamp createdAt = rs.getTimestamp("created_at");
        return new PostRow(
                rs.getLong("id"),
                rs.getString("title"),
                rs.getString("content"),
                rs.getString("author_username"),
                createdAt == null ? Instant.EPOCH : createdAt.toInstant());
    };

    private final JdbcTemplate jdbcTemplate;

    public PostJdbcRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * @param query строка поиска; спецсимволы LIKE экранируются, чтобы {@code %} не означал «всё»
     * @param limit потолок числа строк в ответе
     */
    public List<PostRow> search(String query, int limit) {
        String pattern = "%" + escapeLikeWildcards(query) + "%";
        return jdbcTemplate.query(SEARCH_SQL, ROW_MAPPER, pattern, pattern, limit);
    }

    private static String escapeLikeWildcards(String raw) {
        return raw.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
    }

    /** Строка результата поиска. */
    public record PostRow(Long id, String title, String content, String authorUsername, Instant createdAt) {
    }
}
