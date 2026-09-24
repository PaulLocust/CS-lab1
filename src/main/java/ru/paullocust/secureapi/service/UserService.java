package ru.paullocust.secureapi.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.paullocust.secureapi.domain.UserAccount;
import ru.paullocust.secureapi.dto.UserResponse;
import ru.paullocust.secureapi.exception.ResourceNotFoundException;
import ru.paullocust.secureapi.repository.UserAccountRepository;
import ru.paullocust.secureapi.util.HtmlSanitizer;

import java.util.List;

/** Профиль текущего пользователя и административный список учётных записей. */
@Service
public class UserService {

    private final UserAccountRepository userAccountRepository;
    private final HtmlSanitizer htmlSanitizer;

    public UserService(UserAccountRepository userAccountRepository, HtmlSanitizer htmlSanitizer) {
        this.userAccountRepository = userAccountRepository;
        this.htmlSanitizer = htmlSanitizer;
    }

    /** Имя берётся из токена, а не из параметров запроса. */
    @Transactional(readOnly = true)
    public UserResponse profile(String username) {
        UserAccount account = userAccountRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("Учётная запись не найдена"));
        return toResponse(account);
    }

    /** Только для ADMIN. {@link PreAuthorize} страхует на случай ошибки в правилах маршрутов. */
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional(readOnly = true)
    public List<UserResponse> listUsers() {
        return userAccountRepository.findAllByOrderByIdAsc().stream()
                .map(this::toResponse)
                .toList();
    }

    private UserResponse toResponse(UserAccount account) {
        return new UserResponse(
                account.getId(),
                htmlSanitizer.encodeForHtml(account.getUsername()),
                account.getRole().name(),
                account.isEnabled(),
                account.getCreatedAt());
    }
}
