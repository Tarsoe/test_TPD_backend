package com.example.matching.repository;

import com.example.matching.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(@Param("username") String username);

    Optional<User> findByEmail(@Param("email") String email);

    // Optional<User> findByUsernameOrEmail(@Param("usernameOrEmail") String usernameOrEmail);
    // Optional<User> findByUsernameOrEmail(String username, String email);
    @Query("SELECT u FROM User u WHERE u.username = :input OR u.email = :input")
    Optional<User> findByUsernameOrEmail(@Param("input") String input);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}

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
