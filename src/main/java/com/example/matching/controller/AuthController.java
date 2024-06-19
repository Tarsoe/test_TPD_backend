// package com.example.matching.controller;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.web.bind.annotation.PostMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RestController;

// import com.example.matching.dto.ForgotPasswordRequest;
// import com.example.matching.dto.ResetPasswordRequest;
// import com.example.matching.service.PasswordResetService;

// @RestController
// @RequestMapping("/api/auth")
// public class AuthController {
//     @Autowired
//     private PasswordResetService passwordResetService;

//     @PostMapping("/forgot-password")
//     public ResponseEntity<String> forgotPassword(@RequestBody ForgotPasswordRequest request) {
//         passwordResetService.createPasswordResetToken(request.getEmail());
//         return ResponseEntity.ok("Password reset email sent");
//     }

//     @PostMapping("/reset-password")
//     public ResponseEntity<String> resetPassword(@RequestBody ResetPasswordRequest request) {
//         passwordResetService.resetPassword(request.getToken(), request.getNewPassword());
//         return ResponseEntity.ok("Password has been reset successfully");
//     }
// }
