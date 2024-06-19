// PasswordResetTokenRepository.java
package com.example.matching.repository;

import com.example.matching.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    PasswordResetToken findByToken(String token);
    PasswordResetToken findByUserId(Long userId);
}

// ? End

// package com.example.matching.repository;

// import java.util.Optional;

// import org.springframework.data.jpa.repository.JpaRepository;

// import com.example.matching.model.PasswordResetToken;

// public interface PasswordResetTokenRepository extends
// JpaRepository<PasswordResetToken, Long> {
// Optional<PasswordResetToken> findByToken(String token);

// Optional<PasswordResetToken> findByEmail(String email);
// }

// ! End

// import org.springframework.data.jpa.repository.JpaRepository;

// import com.example.matching.model.PasswordResetToken;

// import java.util.Optional;

// public interface PasswordResetTokenRepository extends
// JpaRepository<PasswordResetToken, Long> {
// Optional<PasswordResetToken> findByToken(String token);
// }
