package ru.paullocust.secureapi.web;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.paullocust.secureapi.dto.LoginRequest;
import ru.paullocust.secureapi.dto.LoginResponse;
import ru.paullocust.secureapi.dto.RegisterRequest;
import ru.paullocust.secureapi.dto.UserResponse;
import ru.paullocust.secureapi.service.AuthService;

/** Публичные эндпоинты аутентификации. */
@RestController
@RequestMapping("/auth")
@Tag(name = "Аутентификация", description = "Вход в систему и регистрация")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    @Operation(summary = "Аутентификация: обменять логин и пароль на JWT")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Токен выдан"),
            @ApiResponse(responseCode = "400", description = "Некорректные данные запроса", content = @Content),
            @ApiResponse(responseCode = "401", description = "Неверный логин или пароль", content = @Content),
            @ApiResponse(responseCode = "429", description = "Слишком много неудачных попыток", content = @Content)
    })
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletRequest httpRequest) {
        LoginResponse response = authService.login(request, clientIp(httpRequest));
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    @Operation(summary = "Регистрация нового пользователя (пароль хешируется BCrypt)")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Пользователь создан"),
            @ApiResponse(responseCode = "400", description = "Пароль не соответствует политике", content = @Content),
            @ApiResponse(responseCode = "409", description = "Логин уже занят", content = @Content)
    })
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    /**
     * Адрес клиента для счётчика попыток. Берём {@code getRemoteAddr()}:
     * {@code X-Forwarded-For} подделывается клиентом и доверять ему можно только за прокси.
     */
    private static String clientIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
