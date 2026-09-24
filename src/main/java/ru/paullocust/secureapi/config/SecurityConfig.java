package ru.paullocust.secureapi.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import ru.paullocust.secureapi.security.JwtAuthenticationFilter;
import ru.paullocust.secureapi.security.RestAccessDeniedHandler;
import ru.paullocust.secureapi.security.RestAuthenticationEntryPoint;

import java.util.List;

/** Конфигурация Spring Security: stateless-доступ по JWT, deny by default, BCrypt, защитные заголовки. */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /** CSP для JSON API: из ответа браузер не должен выполнять ничего. */
    private static final String API_CSP =
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox";

    /** CSP для Swagger UI — странице нужны свои скрипты и стили. */
    private static final String SWAGGER_CSP =
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                    + "img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'";

    private static final long HSTS_MAX_AGE_SECONDS = 31_536_000L;

    /** Стоимость BCrypt: 12 раундов ≈ 250 мс на хеш. */
    private static final int BCRYPT_STRENGTH = 12;

    private final SecurityProperties securityProperties;

    public SecurityConfig(SecurityProperties securityProperties) {
        this.securityProperties = securityProperties;
    }

    /** Swagger UI и OpenAPI: открыты, CSP мягче. В профиле prod springdoc выключен. */
    @Bean
    @Order(1)
    public SecurityFilterChain docsFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**")
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(SWAGGER_CSP))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny));
        return http.build();
    }

    /** Основная цепочка API: JWT, без сессий, доступ только к тому, что разрешено явно. */
    @Bean
    @Order(2)
    public SecurityFilterChain apiFilterChain(HttpSecurity http,
                                              JwtAuthenticationFilter jwtAuthenticationFilter,
                                              RestAuthenticationEntryPoint authenticationEntryPoint,
                                              RestAccessDeniedHandler accessDeniedHandler) throws Exception {
        http
                // CSRF не нужен: cookie не используются, токен приходит в заголовке
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .headers(headers -> headers
                        .contentSecurityPolicy(csp -> csp.policyDirectives(API_CSP))
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                        .referrerPolicy(referrer -> referrer.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER))
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(HSTS_MAX_AGE_SECONDS))
                        .permissionsPolicyHeader(permissions -> permissions
                                .policy("geolocation=(), microphone=(), camera=(), payment=()"))
                        .cacheControl(Customizer.withDefaults()))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/register").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        // всё, что не перечислено выше
                        .anyRequest().denyAll())
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /** BCrypt: соль генерируется сама и хранится внутри хеша. */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(BCryptPasswordEncoder.BCryptVersion.$2B, BCRYPT_STRENGTH);
    }

    /**
     * Сверяет пароль с хешем. Для несуществующего логина всё равно выполняет фиктивную проверку,
     * чтобы по времени ответа нельзя было узнать, есть такой пользователь или нет.
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService,
                                                       PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        provider.setHideUserNotFoundExceptions(true);
        return new ProviderManager(provider);
    }

    /** CORS по белому списку источников, без wildcard. */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(securityProperties.allowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        configuration.setAllowCredentials(false);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
