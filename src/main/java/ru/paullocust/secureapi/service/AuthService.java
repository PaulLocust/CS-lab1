package ru.paullocust.secureapi.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.paullocust.secureapi.domain.Role;
import ru.paullocust.secureapi.domain.UserAccount;
import ru.paullocust.secureapi.dto.LoginRequest;
import ru.paullocust.secureapi.dto.LoginResponse;
import ru.paullocust.secureapi.dto.RegisterRequest;
import ru.paullocust.secureapi.dto.UserResponse;
import ru.paullocust.secureapi.exception.InvalidCredentialsException;
import ru.paullocust.secureapi.exception.TooManyAttemptsException;
import ru.paullocust.secureapi.exception.UsernameAlreadyTakenException;
import ru.paullocust.secureapi.repository.UserAccountRepository;
import ru.paullocust.secureapi.security.JwtService;
import ru.paullocust.secureapi.security.LoginAttemptService;
import ru.paullocust.secureapi.util.LogSanitizer;

import java.time.Duration;
import java.util.List;

/** Вход и регистрация: проверка пароля по хешу, выдача JWT, лимит неудачных попыток. */
@Service
public class AuthService {

    private static final Logger LOG = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final LoginAttemptService loginAttemptService;
    private final UserAccountRepository userAccountRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthenticationManager authenticationManager,
                       JwtService jwtService,
                       LoginAttemptService loginAttemptService,
                       UserAccountRepository userAccountRepository,
                       PasswordEncoder passwordEncoder) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.loginAttemptService = loginAttemptService;
        this.userAccountRepository = userAccountRepository;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Проверяет логин с паролем и выдаёт токен.
     *
     * @param clientIp адрес клиента — часть ключа счётчика неудачных попыток
     * @throws TooManyAttemptsException    действует блокировка по паре «логин+IP»
     * @throws InvalidCredentialsException пара логин/пароль не подошла
     */
    public LoginResponse login(LoginRequest request, String clientIp) {
        String attemptKey = loginAttemptService.key(request.username(), clientIp);

        Duration blockedFor = loginAttemptService.blockedFor(attemptKey);
        if (!blockedFor.isZero()) {
            LOG.warn("Вход заблокирован для '{}': осталось {} c",
                    LogSanitizer.forLog(request.username()), blockedFor.toSeconds());
            throw new TooManyAttemptsException(blockedFor);
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()));

            loginAttemptService.reset(attemptKey);

            UserDetails principal = (UserDetails) authentication.getPrincipal();
            List<String> roles = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();

            String token = jwtService.issueToken(principal);
            LOG.info("Успешный вход пользователя '{}'", LogSanitizer.forLog(principal.getUsername()));

            return LoginResponse.bearer(
                    token,
                    jwtService.accessTokenTtl().toSeconds(),
                    principal.getUsername(),
                    roles);
        } catch (AuthenticationException ex) {
            loginAttemptService.recordFailure(attemptKey);
            LOG.warn("Неудачная попытка входа для '{}'", LogSanitizer.forLog(request.username()));
            // Наружу одна и та же ошибка: по ответу нельзя понять, есть такой пользователь или нет
            throw new InvalidCredentialsException();
        }
    }

    /** Создаёт пользователя с ролью {@link Role#USER}; в БД уходит только хеш пароля. */
    @Transactional
    public UserResponse register(RegisterRequest request) {
        if (userAccountRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyTakenException();
        }

        String passwordHash = passwordEncoder.encode(request.password());
        UserAccount account = userAccountRepository.save(
                new UserAccount(request.username(), passwordHash, Role.USER));

        LOG.info("Зарегистрирован пользователь '{}'", LogSanitizer.forLog(account.getUsername()));
        return new UserResponse(
                account.getId(),
                account.getUsername(),
                account.getRole().name(),
                account.isEnabled(),
                account.getCreatedAt());
    }
}
