package ru.paullocust.secureapi.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import ru.paullocust.secureapi.domain.Post;

/**
 * Записи через ORM. Запросы — JPQL с именованными параметрами: значение не склеивается
 * с текстом запроса, поэтому {@code ' OR 1=1 --} остаётся обычным текстом.
 */
@Repository
public interface PostRepository extends JpaRepository<Post, Long> {

    @Query("""
            SELECT p FROM Post p
             WHERE LOWER(p.title) LIKE LOWER(CONCAT('%', :query, '%'))
                OR LOWER(p.content) LIKE LOWER(CONCAT('%', :query, '%'))
            """)
    Page<Post> search(@Param("query") String query, Pageable pageable);

    long countByAuthorUsername(String authorUsername);
}
