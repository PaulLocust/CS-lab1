package ru.paullocust.secureapi.security;

import org.springframework.stereotype.Service;
import ru.paullocust.secureapi.config.SecurityProperties;

import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Счётчик неудачных входов по паре «логин + IP»: ограничивает и подбор пароля к одному
 * аккаунту, и перебор логинов с одного адреса. Лимит и срок блокировки задаются
 * в {@code app.security.*}, успешный вход сбрасывает счётчик.
 *
 * <p>Хранилище в памяти — на один инстанс. Для кластера счётчик выносят в Redis.</p>
 */
@Service
public class LoginAttemptService {

    /** Чтобы карта не разрасталась при массовом переборе логинов. */
    private static final int MAX_TRACKED_KEYS = 10_000;

    private final Map<String, Attempt> attempts = new ConcurrentHashMap<>();
    private final SecurityProperties properties;

    public LoginAttemptService(SecurityProperties properties) {
        this.properties = properties;
    }

    /** Ключ: логин в нижнем регистре + IP. */
    public String key(String username, String clientIp) {
        String normalizedUser = username == null ? "" : username.toLowerCase(Locale.ROOT);
        String normalizedIp = clientIp == null ? "unknown" : clientIp;
        return normalizedUser + '|' + normalizedIp;
    }

    /** Сколько осталось до конца блокировки; {@link Duration#ZERO}, если её нет. */
    public Duration blockedFor(String key) {
        Attempt attempt = attempts.get(key);
        if (attempt == null || attempt.blockedUntil() == null) {
            return Duration.ZERO;
        }
        Instant now = Instant.now();
        return now.isBefore(attempt.blockedUntil()) ? Duration.between(now, attempt.blockedUntil()) : Duration.ZERO;
    }

    public boolean isBlocked(String key) {
        return !blockedFor(key).isZero();
    }

    /** Считает неудачную попытку и при превышении лимита включает блокировку. */
    public void recordFailure(String key) {
        Instant now = Instant.now();
        Duration lock = properties.loginLockDuration();

        attempts.compute(key, (ignored, current) -> {
            boolean windowExpired = current == null || now.isAfter(current.lastFailureAt().plus(lock));
            int count = windowExpired ? 1 : current.count() + 1;
            Instant blockedUntil = count >= properties.maxLoginAttempts() ? now.plus(lock) : null;
            return new Attempt(count, now, blockedUntil);
        });

        evictStaleEntries(now, lock);
    }

    /** Успешная аутентификация обнуляет счётчик. */
    public void reset(String key) {
        attempts.remove(key);
    }

    private void evictStaleEntries(Instant now, Duration lock) {
        if (attempts.size() <= MAX_TRACKED_KEYS) {
            return;
        }
        attempts.entrySet().removeIf(entry -> {
            Attempt attempt = entry.getValue();
            boolean lockExpired = attempt.blockedUntil() == null || now.isAfter(attempt.blockedUntil());
            return lockExpired && now.isAfter(attempt.lastFailureAt().plus(lock));
        });
    }

    private record Attempt(int count, Instant lastFailureAt, Instant blockedUntil) {
    }
}
