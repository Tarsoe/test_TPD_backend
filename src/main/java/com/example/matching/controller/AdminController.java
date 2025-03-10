// package com.example.matching.controller;

// import com.example.matching.filter.RateLimitingFilter;
// import com.example.matching.model.UserDetailsForAdmin;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.access.annotation.Secured;
// import org.springframework.web.bind.annotation.DeleteMapping;
// import org.springframework.web.bind.annotation.PathVariable;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RestController;

// import java.util.Map;
// import java.util.UUID;

// @RestController
// @RequestMapping("/admin")
// public class AdminController {

//     private final Map<UserDetailsForAdmin, Integer> loginAttempts;
//     private final Map<UserDetailsForAdmin, UUID> accountLockTime;

//     @SuppressWarnings("unchecked")
//     public AdminController(RateLimitingFilter rateLimitingFilter) {
//         // Access loginAttempts and accountLockTime using getter methods
//         this.loginAttempts = (Map<UserDetailsForAdmin, Integer>) (Map<?, ?>) rateLimitingFilter.getLoginAttempts();
//         this.accountLockTime = (Map<UserDetailsForAdmin, UUID>) (Map<?, ?>) rateLimitingFilter.getAccountLockTime();
//     }

//     @Secured("ROLE_ADMIN")
//     @DeleteMapping("/unlock/{identifier}")
//     public ResponseEntity<String> unlockAccount(@PathVariable String identifier) {
//         // Search for the user by username or email
//         UserDetailsForAdmin userToUnlock = findUserByUsernameOrEmail(identifier);
//         if (userToUnlock != null) {
//             loginAttempts.remove(userToUnlock);
//             accountLockTime.remove(userToUnlock);
//             return new ResponseEntity<>("Account unlocked for user: " + identifier, HttpStatus.OK);
//         } else {
//             return new ResponseEntity<>("User not found or not locked", HttpStatus.NOT_FOUND);
//         }
//     }

//     private UserDetailsForAdmin findUserByUsernameOrEmail(String identifier) {
//         return loginAttempts.keySet().stream()
//                 .filter(user -> user.getUsername().equals(identifier) || user.getEmail().equals(identifier))
//                 .findFirst()
//                 .orElse(null);
//     }
// }
