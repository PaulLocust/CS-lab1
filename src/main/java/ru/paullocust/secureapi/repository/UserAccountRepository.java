package ru.paullocust.secureapi.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import ru.paullocust.secureapi.domain.UserAccount;

import java.util.List;
import java.util.Optional;

/** Учётные записи. Spring Data строит запрос по имени метода и передаёт аргументы параметрами. */
@Repository
public interface UserAccountRepository extends JpaRepository<UserAccount, Long> {

    /** Используется при аутентификации. */
    Optional<UserAccount> findByUsername(String username);

    boolean existsByUsername(String username);

    List<UserAccount> findAllByOrderByIdAsc();
}
