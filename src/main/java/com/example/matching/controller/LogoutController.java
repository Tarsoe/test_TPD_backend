// // LogoutController.java
// package com.example.matching.controller;

// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RestController;

// @RestController
// @RequestMapping("/logout")
// public class LogoutController {

//     @PostMapping
//     public ResponseEntity<String> logout() {
//         Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//         if (auth != null) {
//             SecurityContextHolder.clearContext();
//         }
//         return new ResponseEntity<>("You have been logged out successfully. tarso", HttpStatus.OK);
//     }
// }
