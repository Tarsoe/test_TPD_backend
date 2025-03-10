package com.example.matching.controller;

import com.example.matching.model.PasswordResetToken;
import com.example.matching.model.User;
import com.example.matching.service.EmailService;
import com.example.matching.service.PasswordResetTokenService;
import com.example.matching.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/password-reset")
public class PasswordResetController {

    @Autowired
    private PasswordResetTokenService passwordResetTokenService;

    @Autowired
    private UserService userService;

    @Autowired
    private EmailService emailService;

    @PostMapping("/request")
    public Map<String, String> requestPasswordReset(@RequestParam("email") String userEmail) {
        User user = userService.findUserByEmail(userEmail)
                .orElseThrow(() -> new IllegalArgumentException("No user found with this email. From backend"));
        String token = passwordResetTokenService.createPasswordResetTokenForUser(user);
        emailService.sendPasswordResetEmail(userEmail, token);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Password reset token has been sent to your email. \n Click next to validate token");
        return response;
    }

    @GetMapping("/validate")
    public Map<String, String> validateToken(@RequestParam("token") String token) {
        PasswordResetToken passToken = passwordResetTokenService.validatePasswordResetToken(token);
        if (passToken == null) {
            throw new IllegalArgumentException("Invalid or expired token.");
        }
        Map<String, String> response = new HashMap<>();
        response.put("message", "Token is valid.");
        return response;
    }

    @PostMapping("/reset")
    public Map<String, String> resetPassword(@RequestParam("token") String token,
            @RequestParam("password") String newPassword) {
        PasswordResetToken passToken = passwordResetTokenService.validatePasswordResetToken(token);
        if (passToken == null) {
            throw new IllegalArgumentException("Invalid or expired token.");
        }
        User user = passToken.getUser();
        userService.updatePassword(user, newPassword);
        passwordResetTokenService.deleteToken(passToken);

        Map<String, String> response = new HashMap<>();
        response.put("message", "Password has been reset successfully.");
        return response;
    }
}

// ! End

// // PasswordResetController.java
// package com.example.matching.controller;

// import com.example.matching.model.PasswordResetRequest;
// import com.example.matching.model.PasswordResetToken;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.PasswordResetTokenService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.web.bind.annotation.*;

// import java.util.Optional;

// @RestController
// public class PasswordResetController {

// @Autowired
// private UserRepository userRepository;

// @Autowired
// private PasswordResetTokenService tokenService;

// @Autowired
// private PasswordEncoder passwordEncoder;

// @PostMapping("/password-reset-request")
// public ResponseEntity<?> requestPasswordReset(@RequestBody
// PasswordResetRequest passwordResetRequest) {
// Optional<User> user =
// userRepository.findByEmail(passwordResetRequest.getEmail());
// if (user.isPresent()) {
// String token = tokenService.createPasswordResetTokenForUser(user.get());
// // Send email logic here (using your preferred method)
// return ResponseEntity.ok("Password reset email sent");
// }
// return ResponseEntity.badRequest().body("Email address not found");
// }

// @PostMapping("/reset-password")
// public ResponseEntity<?> resetPassword(@RequestParam("token") String token,
// @RequestParam("password") String password) {
// PasswordResetToken passToken =
// tokenService.validatePasswordResetToken(token);
// if (passToken != null) {
// User user = passToken.getUser();
// user.setPassword(passwordEncoder.encode(password));
// userRepository.save(user);
// return ResponseEntity.ok("Password successfully reset");
// }
// return ResponseEntity.badRequest().body("Invalid or expired token");
// }
// }

// ! End

// package com.example.matching.controller;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.web.bind.annotation.*;

// import com.example.matching.model.PasswordResetToken;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.EmailService;
// import com.example.matching.service.PasswordResetTokenService;

// import jakarta.mail.MessagingException;

// // import javax.mail.MessagingException;
// import java.util.Optional;

// @RestController
// @RequestMapping("/api/auth")
// public class PasswordResetController {

// @Autowired
// private UserRepository userRepository;

// @Autowired
// private PasswordResetTokenService tokenService;

// @Autowired
// private EmailService emailService;

// @PostMapping("/forgot-password")
// public String forgotPassword(@RequestParam("email") String userEmail) {
// Optional<User> userOptional = userRepository.findByEmail(userEmail);
// if (!userOptional.isPresent()) {
// return "No user found with that email address.";
// }

// User user = userOptional.get();
// PasswordResetToken token = tokenService.createToken(user);

// String resetUrl = "http://localhost:8080/api/auth/reset-password?token=" +
// token.getToken();
// try {
// emailService.sendEmail(user.getEmail(), "Password Reset Request",
// "To reset your password, click the link below:\n" + resetUrl);
// } catch (MessagingException e) {
// e.printStackTrace();
// return "Failed to send email.";
// }

// return "Password reset email sent.";
// }

// @GetMapping("/reset-password")
// public String showResetPasswordPage(@RequestParam("token") String token) {
// Optional<PasswordResetToken> tokenOptional = tokenService.getToken(token);
// if (!tokenOptional.isPresent() ||
// tokenService.isTokenExpired(tokenOptional.get())) {
// return "Invalid or expired token.";
// }
// return "Reset your password.";
// }

// @PostMapping("/reset-password")
// public String resetPassword(@RequestParam("token") String token,
// @RequestParam("password") String newPassword) {
// Optional<PasswordResetToken> tokenOptional = tokenService.getToken(token);
// if (!tokenOptional.isPresent() ||
// tokenService.isTokenExpired(tokenOptional.get())) {
// return "Invalid or expired token.";
// }

// User user = tokenOptional.get().getUser();
// user.setPassword(newPassword); // Ensure you hash the password before saving
// userRepository.save(user);

// return "Password reset successfully.";
// }
// }
