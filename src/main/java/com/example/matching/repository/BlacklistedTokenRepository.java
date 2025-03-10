// BlacklistedTokenRepository.java
package com.example.matching.repository;

import com.example.matching.model.BlacklistedToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, UUID> {
    Optional<BlacklistedToken> findByToken(String token);
}
// public interface BlacklistedTokenRepository extends JpaRepository<BlacklistedToken, Long> {
//     Optional<BlacklistedToken> findByToken(String token);
// }
