package ru.paullocust.secureapi.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import ru.paullocust.secureapi.config.JwtProperties;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Выпуск и проверка JWT. Подпись HS256, при разборе проверяются подпись, срок действия,
 * издатель и аудитория. Алгоритм задан явно, поэтому подмена {@code alg} не проходит.
 */
@Service
public final class JwtService {

    /** Claim со списком ролей. */
    public static final String ROLES_CLAIM = "roles";

    /** Допустимое расхождение часов. */
    private static final long CLOCK_SKEW_SECONDS = 30L;

    private final SecretKey signingKey;
    private final JwtParser parser;
    private final JwtProperties properties;

    public JwtService(JwtProperties properties) {
        this.properties = properties;
        byte[] secretBytes = properties.secret().getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < 32) {
            throw new IllegalStateException(
                    "app.jwt.secret слишком короткий: для HS256 нужен ключ не менее 256 бит (32 байта)");
        }
        this.signingKey = Keys.hmacShaKeyFor(secretBytes);
        this.parser = Jwts.parser()
                .verifyWith(signingKey)
                .requireIssuer(properties.issuer())
                .requireAudience(properties.audience())
                .clockSkewSeconds(CLOCK_SKEW_SECONDS)
                .build();
    }

    /**
     * Выпускает access-токен. В payload только имя пользователя и роли:
     * он закодирован Base64URL и читается кем угодно, секретам там не место.
     */
    public String issueToken(UserDetails user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(properties.accessTokenTtl());
        List<String> roles = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getUsername())
                .issuer(properties.issuer())
                .audience().add(properties.audience()).and()
                .issuedAt(Date.from(now))
                .notBefore(Date.from(now))
                .expiration(Date.from(expiresAt))
                .claim(ROLES_CLAIM, roles)
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * @throws JwtException если подпись неверна, срок истёк либо iss/aud не совпадают
     */
    public Jws<Claims> parse(String token) {
        return parser.parseSignedClaims(token);
    }

    /** Роли из проверенного токена. */
    public List<String> extractRoles(Claims claims) {
        Object raw = claims.get(ROLES_CLAIM);
        if (raw instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of();
    }

    /** Время жизни токена — отдаётся клиенту в ответе на login. */
    public Duration accessTokenTtl() {
        return properties.accessTokenTtl();
    }
}
