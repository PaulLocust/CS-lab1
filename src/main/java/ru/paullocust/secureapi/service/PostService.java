package ru.paullocust.secureapi.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.paullocust.secureapi.domain.Post;
import ru.paullocust.secureapi.domain.Role;
import ru.paullocust.secureapi.dto.CreatePostRequest;
import ru.paullocust.secureapi.dto.PageResponse;
import ru.paullocust.secureapi.dto.PostResponse;
import ru.paullocust.secureapi.exception.ResourceNotFoundException;
import ru.paullocust.secureapi.repository.PostJdbcRepository;
import ru.paullocust.secureapi.repository.PostRepository;
import ru.paullocust.secureapi.util.HtmlSanitizer;
import ru.paullocust.secureapi.util.LogSanitizer;

import java.util.List;

/**
 * Логика работы с записями: чистит ввод от разметки, экранирует всё, что уходит наружу,
 * и проверяет владельца при удалении.
 */
@Service
public class PostService {

    private static final Logger LOG = LoggerFactory.getLogger(PostService.class);

    private final PostRepository postRepository;
    private final PostJdbcRepository postJdbcRepository;
    private final HtmlSanitizer htmlSanitizer;

    public PostService(PostRepository postRepository,
                       PostJdbcRepository postJdbcRepository,
                       HtmlSanitizer htmlSanitizer) {
        this.postRepository = postRepository;
        this.postJdbcRepository = postJdbcRepository;
        this.htmlSanitizer = htmlSanitizer;
    }

    /** Список записей постранично; с непустым {@code query} — поиск через JPQL. */
    @Transactional(readOnly = true)
    public PageResponse<PostResponse> list(String query, Pageable pageable) {
        Page<Post> page = (query == null || query.isBlank())
                ? postRepository.findAll(pageable)
                : postRepository.search(query, pageable);
        return PageResponse.from(page, this::toResponse);
    }

    /** Тот же поиск, но через JDBC с PreparedStatement. */
    @Transactional(readOnly = true)
    public List<PostResponse> search(String query, int limit) {
        return postJdbcRepository.search(query == null ? "" : query, limit).stream()
                .map(row -> new PostResponse(
                        row.id(),
                        htmlSanitizer.encodeForHtml(row.title()),
                        htmlSanitizer.encodeForHtml(row.content()),
                        htmlSanitizer.encodeForHtml(row.authorUsername()),
                        row.createdAt()))
                .toList();
    }

    /** Создаёт запись, вырезав из заголовка и текста разметку. */
    @Transactional
    public PostResponse create(CreatePostRequest request, String authorUsername) {
        String title = htmlSanitizer.sanitize(request.title());
        String content = htmlSanitizer.sanitize(request.content());

        if (title.isEmpty() || content.isEmpty()) {
            throw new IllegalArgumentException("После удаления разметки заголовок или текст оказались пустыми");
        }

        Post saved = postRepository.save(new Post(title, content, authorUsername));
        LOG.info("Пользователь '{}' создал запись id={}", LogSanitizer.forLog(authorUsername), saved.getId());
        return toResponse(saved);
    }

    /** Удаление доступно автору записи и роли ADMIN. Владелец сверяется по данным из БД. */
    @Transactional
    public void delete(long postId, Authentication authentication) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new ResourceNotFoundException("Запись не найдена"));

        boolean isAdmin = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(Role.ADMIN.authority()::equals);
        boolean isOwner = post.getAuthorUsername().equals(authentication.getName());

        if (!isAdmin && !isOwner) {
            LOG.warn("Отказано в удалении записи id={} пользователю '{}'",
                    postId, LogSanitizer.forLog(authentication.getName()));
            throw new AccessDeniedException("Удалять можно только собственные записи");
        }

        postRepository.delete(post);
        LOG.info("Запись id={} удалена пользователем '{}'", postId, LogSanitizer.forLog(authentication.getName()));
    }

    private PostResponse toResponse(Post post) {
        return new PostResponse(
                post.getId(),
                htmlSanitizer.encodeForHtml(post.getTitle()),
                htmlSanitizer.encodeForHtml(post.getContent()),
                htmlSanitizer.encodeForHtml(post.getAuthorUsername()),
                post.getCreatedAt());
    }
}
