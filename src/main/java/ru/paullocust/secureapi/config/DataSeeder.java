package ru.paullocust.secureapi.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import ru.paullocust.secureapi.domain.Post;
import ru.paullocust.secureapi.domain.Role;
import ru.paullocust.secureapi.domain.UserAccount;
import ru.paullocust.secureapi.repository.PostRepository;
import ru.paullocust.secureapi.repository.UserAccountRepository;
import ru.paullocust.secureapi.util.LogSanitizer;

import java.util.List;

/**
 * Наполняет БД демонстрационными данными при старте. Логины и пароли берутся
 * из {@code app.seed.*}, в базу уходит только хеш пароля.
 */
@Component
public class DataSeeder implements ApplicationRunner {

    private static final Logger LOG = LoggerFactory.getLogger(DataSeeder.class);

    private final UserAccountRepository userAccountRepository;
    private final PostRepository postRepository;
    private final PasswordEncoder passwordEncoder;
    private final SeedProperties seedProperties;

    public DataSeeder(UserAccountRepository userAccountRepository,
                      PostRepository postRepository,
                      PasswordEncoder passwordEncoder,
                      SeedProperties seedProperties) {
        this.userAccountRepository = userAccountRepository;
        this.postRepository = postRepository;
        this.passwordEncoder = passwordEncoder;
        this.seedProperties = seedProperties;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedUsers();
        seedPosts();
    }

    private void seedUsers() {
        if (userAccountRepository.count() > 0) {
            return;
        }
        userAccountRepository.saveAll(List.of(
                new UserAccount(seedProperties.adminUsername(),
                        passwordEncoder.encode(seedProperties.adminPassword()), Role.ADMIN),
                new UserAccount(seedProperties.userUsername(),
                        passwordEncoder.encode(seedProperties.userPassword()), Role.USER)));
        LOG.info("Созданы демонстрационные учётные записи: {} (ADMIN), {} (USER)",
                LogSanitizer.forLog(seedProperties.adminUsername()),
                LogSanitizer.forLog(seedProperties.userUsername()));
    }

    private void seedPosts() {
        if (postRepository.count() > 0) {
            return;
        }
        postRepository.saveAll(List.of(
                new Post("OWASP Top 10 2021",
                        "A01 Broken Access Control, A03 Injection и A07 Identification and Authentication Failures "
                                + "разбираются в этой лабораторной работе.",
                        seedProperties.adminUsername()),
                new Post("Параметризованные запросы",
                        "PreparedStatement передаёт данные отдельно от текста SQL, поэтому кавычка в поиске "
                                + "остаётся обычным символом.",
                        seedProperties.adminUsername()),
                new Post("Зачем нужен BCrypt",
                        "Медленная функция с солью и настраиваемой стоимостью защищает базу паролей "
                                + "от перебора по радужным таблицам.",
                        seedProperties.userUsername())));
        LOG.info("Загружены демонстрационные записи: {}", postRepository.count());
    }
}
