package ru.paullocust.secureapi.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** Запись, с которой работает {@code /api/data}. Заголовок и текст хранятся уже без HTML. */
@Entity
@Table(name = "posts")
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "title", nullable = false, length = 120)
    private String title;

    @Column(name = "content", nullable = false, length = 5000)
    private String content;

    /** Владелец записи: по нему проверяются права на удаление. */
    @Column(name = "author_username", nullable = false, length = 64)
    private String authorUsername;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    /** Для JPA. */
    protected Post() {
    }

    public Post(String title, String content, String authorUsername) {
        this.title = title;
        this.content = content;
        this.authorUsername = authorUsername;
        this.createdAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public String getContent() {
        return content;
    }

    public String getAuthorUsername() {
        return authorUsername;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
