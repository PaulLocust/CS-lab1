package ru.paullocust.secureapi.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.paullocust.secureapi.domain.UserAccount;
import ru.paullocust.secureapi.repository.UserAccountRepository;

/** Отдаёт Spring Security учётную запись вместе с хешем пароля для сверки. */
@Service
public class AppUserDetailsService implements UserDetailsService {

    private final UserAccountRepository userAccountRepository;

    public AppUserDetailsService(UserAccountRepository userAccountRepository) {
        this.userAccountRepository = userAccountRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        UserAccount account = userAccountRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Учётная запись не найдена"));

        return User.withUsername(account.getUsername())
                .password(account.getPasswordHash())
                .authorities(new SimpleGrantedAuthority(account.getRole().authority()))
                .disabled(!account.isEnabled())
                .build();
    }
}
