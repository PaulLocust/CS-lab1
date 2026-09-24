package ru.paullocust.secureapi.web;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ru.paullocust.secureapi.dto.CreatePostRequest;
import ru.paullocust.secureapi.dto.PageResponse;
import ru.paullocust.secureapi.dto.PostResponse;
import ru.paullocust.secureapi.service.PostService;

import java.util.List;

/** Эндпоинты работы с записями. Доступны только с валидным JWT. */
@RestController
@RequestMapping("/api")
@Validated
@Tag(name = "Данные", description = "Записи пользователей; требуется JWT")
@SecurityRequirement(name = "bearer-jwt")
public class DataController {

    /** Потолок размера страницы: одним запросом всю таблицу не выгрузить. */
    private static final int MAX_PAGE_SIZE = 50;

    private static final int MAX_SEARCH_RESULTS = 20;

    private final PostService postService;

    public DataController(PostService postService) {
        this.postService = postService;
    }

    @GetMapping("/data")
    @Operation(summary = "Список записей (только для аутентифицированных пользователей)")
    public PageResponse<PostResponse> list(
            @RequestParam(required = false) @Size(max = 100, message = "Поисковая строка не длиннее 100 символов") String query,
            @RequestParam(defaultValue = "0") @Min(0) int page,
            @RequestParam(defaultValue = "10") @Min(1) @Max(MAX_PAGE_SIZE) int size) {

        return postService.list(query, PageRequest.of(page, size, Sort.by(Sort.Direction.DESC, "createdAt")));
    }

    @GetMapping("/data/search")
    @Operation(summary = "Поиск записей параметризованным SQL-запросом")
    public List<PostResponse> search(
            @RequestParam @NotBlank @Size(max = 100, message = "Поисковая строка не длиннее 100 символов") String query) {

        return postService.search(query, MAX_SEARCH_RESULTS);
    }

    /** Автор берётся из токена, а не из тела запроса — иначе можно писать от чужого имени. */
    @PostMapping("/data")
    @Operation(summary = "Создать запись (ввод очищается от HTML)")
    public ResponseEntity<PostResponse> create(@Valid @RequestBody CreatePostRequest request,
                                               Authentication authentication) {
        PostResponse created = postService.create(request, authentication.getName());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @DeleteMapping("/data/{id}")
    @Operation(summary = "Удалить свою запись (администратор может удалить любую)")
    public ResponseEntity<Void> delete(@PathVariable @Positive long id, Authentication authentication) {
        postService.delete(id, authentication);
        return ResponseEntity.noContent().build();
    }
}
