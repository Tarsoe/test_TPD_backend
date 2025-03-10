
//! Without Rate Limiting Login Attempts
package com.example.matching.repository;

import com.example.matching.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.*;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByUsername(@Param("username") String username);

    Optional<User> findByEmail(@Param("email") String email);

    @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
    Optional<User> findByUsernameOrEmail(@Param("input") String input);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    Optional<User> findById(UUID userId); // Already fine
}

// //! With Rate Limiting Login Attempts
// package com.example.matching.repository;

// import com.example.matching.model.User;
// import org.springframework.data.jpa.repository.JpaRepository;
// import org.springframework.data.jpa.repository.Modifying;
// import org.springframework.data.jpa.repository.Query;
// import org.springframework.data.repository.query.Param;

// import java.util.*;

// public interface UserRepository extends JpaRepository<User, UUID> {
//     Optional<User> findByUsername(@Param("username") String username);

//     Optional<User> findByEmail(@Param("email") String email);

//     @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
//     Optional<User> findByUsernameOrEmail(@Param("input") String input);

//     boolean existsByUsername(String username);

//     boolean existsByEmail(String email);

//     Optional<User> findById(UUID userId); // Already fine

//     // Method to reset failed attempts
//     // @Modifying
//     // @Query("UPDATE User u SET u.failedLoginAttempts = 0 WHERE u.id = :userId")
//     // void resetFailedLoginAttempts(@Param("userId") UUID userId);

//     @Modifying
//     @Query("UPDATE User u SET u.failedLoginAttempts = 0 WHERE u.id = :userId")
//     void resetFailedLoginAttempts(@Param("userId") UUID userId);

//     // Method to update failed login attempts
//     @Modifying
//     @Query("UPDATE User u SET u.failedLoginAttempts = :attempts WHERE u.id = :userId")
//     void updateFailedLoginAttempts(@Param("userId") UUID userId, @Param("attempts") int attempts);

//     // Method to lock user account and set lock time
//     // @Modifying
//     // @Query("UPDATE User u SET u.accountLocked = true, u.lockTime = :lockTime
//     // WHERE u.id = :userId")
//     // void lockUserAccount(@Param("userId") UUID userId, @Param("lockTime") long
//     // lockTime);
//     @Modifying
//     @Query("UPDATE User u SET u.accountLocked = true, u.lockTime = :lockTime WHERE u.id = :userId")
//     void lockUserAccount(@Param("userId") UUID userId, @Param("lockTime") long lockTime);

//     // Method to unlock user account (if needed)
//     @Modifying
//     @Query("UPDATE User u SET u.accountLocked = false WHERE u.id = :userId")
//     void unlockUserAccount(@Param("userId") UUID userId);

//     // Method to fetch all locked users
//     @Query("SELECT u FROM User u WHERE u.accountLocked = true")
//     List<User> findAllLockedUsers();
// }

//! End
// public interface UserRepository extends JpaRepository<User, UUID> {
// Optional<User> findByUsername(@Param("username") String username);

// Optional<User> findByEmail(@Param("email") String email);

// @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
// Optional<User> findByUsernameOrEmail(@Param("input") String input);

// boolean existsByUsername(String username);

// boolean existsByEmail(String email);

// Optional<User> findById(UUID userId); // Add this method

// // Method to lock user account
// void lockUserAccount(UUID id, boolean accountLocked, long lockTime);

// // Method to reset failed attempts
// // void resetFailedLoginAttempts(UUID id);
// @Modifying
// @Query("UPDATE User u SET u.failedLoginAttempts = 0 WHERE u.id = :userId")
// void resetFailedLoginAttempts(@Param("userId") UUID userId);

// void updateFailedLoginAttempts(UUID id, int attempts);

// void lockUserAccount(UUID id, long lockTime);

// // Method to fetch all locked users
// @Query("SELECT u FROM User u WHERE u.accountLocked = true")
// List<User> findAllLockedUsers(); // Add this method

// }

// ! Still Long id
// package com.example.matching.repository;

// import com.example.matching.model.User;
// import org.springframework.data.jpa.repository.JpaRepository;
// import org.springframework.data.jpa.repository.Query;
// import org.springframework.data.repository.query.Param;

// import java.util.Optional;

// public interface UserRepository extends JpaRepository<User, Long> {
// Optional<User> findByUsername(@Param("username") String username);

// Optional<User> findByEmail(@Param("email") String email);

// @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
// Optional<User> findByUsernameOrEmail(@Param("input") String input);

// boolean existsByUsername(String username);

// boolean existsByEmail(String email);

// Optional<User> findById(Long userId); // Add this method
// }

// ! End below code is good

// package com.example.matching.repository;

// import com.example.matching.model.User;
// import org.springframework.data.jpa.repository.JpaRepository;
// import org.springframework.data.jpa.repository.Query;
// import org.springframework.data.repository.query.Param;

// import java.util.Optional;

// public interface UserRepository extends JpaRepository<User, Long> {
// Optional<User> findByUsername(@Param("username") String username);

// Optional<User> findByEmail(@Param("email") String email);

// @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
// Optional<User> findByUsernameOrEmail(@Param("input") String input);

// boolean existsByUsername(String username);

// boolean existsByEmail(String email);
// }

// ! End below code is good

// package com.example.matching.repository;

// import com.example.matching.model.User;
// import org.springframework.data.jpa.repository.JpaRepository;
// import org.springframework.data.jpa.repository.Query;
// import org.springframework.data.repository.query.Param;

// import java.util.Optional;

// public interface UserRepository extends JpaRepository<User, Long> {
// Optional<User> findByUsername(@Param("username") String username);

// Optional<User> findByEmail(@Param("email") String email);

// // Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String
// usernameOrEmail);
// // Optional<User> findByUsernameOrEmail(String username, String email);
// @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
// Optional<User> findByUsernameOrEmail(@Param("input") String input);

// boolean existsByUsername(String username);

// boolean existsByEmail(String email);
// }

// ! End

// package com.example.matching.repository;

// import com.example.matching.model.User;
// import org.springframework.data.jpa.repository.JpaRepository;
// import org.springframework.data.jpa.repository.Query;
// import org.springframework.data.repository.query.Param;
// import org.springframework.stereotype.Repository;

// import java.util.Optional;

// @Repository
// public interface UserRepository extends JpaRepository<User, Long> {
// Optional<User> findByUsername(String username);

// Optional<User> findByEmail(String email);

// // Optional<User> findByUsernameOrEmail(String username, String email);
// @Query("SELECT u FROM User u WHERE u.username = :usernameOrEmail OR u.email =
// :usernameOrEmail")
// Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String
// usernameOrEmail);

// boolean existsByUsername(String username);

// boolean existsByEmail(String email);

// // User findByUsername(String username);
// }

// ! End

// package com.example.matching.repository;

// import com.example.matching.model.User;
// import org.springframework.data.jpa.repository.JpaRepository;

// public interface UserRepository extends JpaRepository<User, Long> {
// boolean existsByUsername(String username);

// boolean existsByEmail(String email);

// User findByUsername(String username);
// }

// package com.example.matching.repository;

// // UserRepository.java
// import org.springframework.data.jpa.repository.JpaRepository;

// import com.example.matching.model.User;

// public interface UserRepository extends JpaRepository<User, Long> {
// // You can add custom query methods here if needed
// boolean existsByUsername(String username);

// boolean existsByEmail(String email);
// }
