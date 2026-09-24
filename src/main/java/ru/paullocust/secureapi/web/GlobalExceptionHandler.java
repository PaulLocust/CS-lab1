package ru.paullocust.secureapi.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import ru.paullocust.secureapi.dto.ApiErrorResponse;
import ru.paullocust.secureapi.exception.InvalidCredentialsException;
import ru.paullocust.secureapi.exception.ResourceNotFoundException;
import ru.paullocust.secureapi.exception.TooManyAttemptsException;
import ru.paullocust.secureapi.exception.UsernameAlreadyTakenException;
import ru.paullocust.secureapi.util.LogSanitizer;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/** Обработка ошибок API: подробности уходят в лог, наружу — код и общая формулировка. */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** Значение для лога: без CR/LF и без «простыни» на весь экран. */
    private static String safe(String value) {
        return LogSanitizer.forLog(value, LogSanitizer.MESSAGE_MAX_LENGTH);
    }

    /** Валидация тела запроса: разбор по полям можно отдать клиенту. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException ex,
                                                             HttpServletRequest request) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.putIfAbsent(fieldError.getField(), fieldError.getDefaultMessage());
        }
        ApiErrorResponse body = new ApiErrorResponse(
                Instant.now(),
                HttpStatus.BAD_REQUEST.value(),
                "validation_error",
                "Запрос не прошёл валидацию",
                request.getRequestURI(),
                fieldErrors);
        return ResponseEntity.badRequest().body(body);
    }

    /** Ошибки валидации query-параметров (@RequestParam / @PathVariable). */
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ApiErrorResponse> handleConstraintViolation(ConstraintViolationException ex,
                                                                      HttpServletRequest request) {
        LOG.debug("Некорректные параметры запроса: {}", safe(ex.getMessage()));
        return ResponseEntity.badRequest().body(ApiErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "validation_error",
                "Некорректные параметры запроса",
                request.getRequestURI()));
    }

    /** Обязательный query-параметр не передан или значение не того типа. */
    @ExceptionHandler({MissingServletRequestParameterException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<ApiErrorResponse> handleBadRequestParameter(Exception ex, HttpServletRequest request) {
        LOG.debug("Некорректный параметр запроса: {}", safe(ex.getMessage()));
        return ResponseEntity.badRequest().body(ApiErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "bad_request",
                "Некорректные параметры запроса",
                request.getRequestURI()));
    }

    /** Метод не поддерживается эндпоинтом. */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> handleMethodNotSupported(HttpRequestMethodNotSupportedException ex,
                                                                     HttpServletRequest request) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED);
        var supported = ex.getSupportedHttpMethods();
        if (supported != null && !supported.isEmpty()) {
            response.allow(supported.toArray(new HttpMethod[0]));
        }
        return response.body(ApiErrorResponse.of(
                HttpStatus.METHOD_NOT_ALLOWED.value(),
                "method_not_allowed",
                "HTTP-метод не поддерживается этим эндпоинтом",
                request.getRequestURI()));
    }

    /** Неподдерживаемый Content-Type: API принимает только JSON. */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiErrorResponse> handleUnsupportedMediaType(HttpMediaTypeNotSupportedException ex,
                                                                       HttpServletRequest request) {
        LOG.debug("Неподдерживаемый Content-Type: {}", safe(String.valueOf(ex.getContentType())));
        return ResponseEntity.status(HttpStatus.UNSUPPORTED_MEDIA_TYPE).body(ApiErrorResponse.of(
                HttpStatus.UNSUPPORTED_MEDIA_TYPE.value(),
                "unsupported_media_type",
                "Тело запроса должно передаваться как application/json",
                request.getRequestURI()));
    }

    /** Некорректный JSON в теле запроса. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ApiErrorResponse> handleUnreadable(HttpMessageNotReadableException ex,
                                                             HttpServletRequest request) {
        LOG.debug("Не удалось разобрать тело запроса: {}", safe(ex.getMessage()));
        return ResponseEntity.badRequest().body(ApiErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "malformed_request",
                "Тело запроса должно быть корректным JSON",
                request.getRequestURI()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ApiErrorResponse> handleIllegalArgument(IllegalArgumentException ex,
                                                                  HttpServletRequest request) {
        return ResponseEntity.badRequest().body(ApiErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                "bad_request",
                ex.getMessage(),
                request.getRequestURI()));
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidCredentials(InvalidCredentialsException ex,
                                                                     HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ApiErrorResponse.of(
                HttpStatus.UNAUTHORIZED.value(),
                "invalid_credentials",
                ex.getMessage(),
                request.getRequestURI()));
    }

    /** Блокировка после серии неудачных попыток входа. */
    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<ApiErrorResponse> handleTooManyAttempts(TooManyAttemptsException ex,
                                                                  HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(ex.getRetryAfterSeconds()))
                .body(ApiErrorResponse.of(
                        HttpStatus.TOO_MANY_REQUESTS.value(),
                        "too_many_attempts",
                        ex.getMessage(),
                        request.getRequestURI()));
    }

    @ExceptionHandler(UsernameAlreadyTakenException.class)
    public ResponseEntity<ApiErrorResponse> handleUsernameTaken(UsernameAlreadyTakenException ex,
                                                                HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ApiErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                "username_taken",
                ex.getMessage(),
                request.getRequestURI()));
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> handleNotFound(ResourceNotFoundException ex,
                                                           HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiErrorResponse.of(
                HttpStatus.NOT_FOUND.value(),
                "not_found",
                ex.getMessage(),
                request.getRequestURI()));
    }

    /** Аутентифицирован, но прав не хватает (например, чужая запись или админский эндпоинт). */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException ex,
                                                               HttpServletRequest request) {
        LOG.warn("Отказ в доступе к {}: {}", safe(request.getRequestURI()), safe(ex.getMessage()));
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ApiErrorResponse.of(
                HttpStatus.FORBIDDEN.value(),
                "forbidden",
                "Недостаточно прав для выполнения операции",
                request.getRequestURI()));
    }

    /** Всё непредвиденное: подробности только в лог. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception ex, HttpServletRequest request) {
        LOG.error("Необработанная ошибка при обращении к {}", safe(request.getRequestURI()), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ApiErrorResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "internal_error",
                "Внутренняя ошибка сервера",
                request.getRequestURI()));
    }
}
