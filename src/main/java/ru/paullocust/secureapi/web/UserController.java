package ru.paullocust.secureapi.web;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.paullocust.secureapi.dto.UserResponse;
import ru.paullocust.secureapi.service.UserService;

import java.util.List;

/** Профиль текущего пользователя и админский список учётных записей. */
@RestController
@RequestMapping("/api")
@Tag(name = "Пользователи", description = "Профиль и администрирование; требуется JWT")
@SecurityRequirement(name = "bearer-jwt")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    @Operation(summary = "Профиль текущего пользователя (по JWT)")
    public UserResponse me(Authentication authentication) {
        return userService.profile(authentication.getName());
    }

    @GetMapping("/users")
    @Operation(summary = "Список пользователей (только ADMIN)")
    public List<UserResponse> users() {
        return userService.listUsers();
    }
}
