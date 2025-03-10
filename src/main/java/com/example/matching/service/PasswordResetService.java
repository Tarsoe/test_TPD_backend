// package com.example.matching.service;

// import java.util.Date;
// import java.util.Optional;
// import java.util.UUID;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.mail.SimpleMailMessage;
// import org.springframework.mail.javamail.JavaMailSender;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.stereotype.Service;

// import com.example.matching.model.PasswordResetToken;
// import com.example.matching.model.User;
// import com.example.matching.repository.PasswordResetTokenRepository;
// import com.example.matching.repository.UserRepository;

// @Service
// public class PasswordResetService {
//     @Autowired
//     private UserRepository userRepository;

//     @Autowired
//     private PasswordResetTokenRepository tokenRepository;

//     @Autowired
//     private JavaMailSender mailSender;

//     @Value("${reset.token.expiry.minutes}")
//     private int tokenExpiryMinutes;

//     public void createPasswordResetToken(String email) {
//         Optional<User> userOptional = userRepository.findByEmail(email);
//         if (!userOptional.isPresent()) {
//             throw new UsernameNotFoundException("User not found with email: " + email);
//         }

//         User user = userOptional.get();
//         String token = UUID.randomUUID().toString();
//         PasswordResetToken resetToken = new PasswordResetToken();
//         resetToken.setToken(token);
//         resetToken.setEmail(email);
//         resetToken.setExpiryDate(new Date(System.currentTimeMillis() + tokenExpiryMinutes * 60 * 1000));
//         tokenRepository.save(resetToken);

//         // Send the email with the token
//         sendPasswordResetEmail(email, token);
//     }

//     public void sendPasswordResetEmail(String email, String token) {
//         String resetUrl = "http://yourfrontend.com/reset-password?token=" + token;
//         SimpleMailMessage message = new SimpleMailMessage();
//         message.setTo(email);
//         message.setSubject("Password Reset Request");
//         message.setText("To reset your password, click the link below:\n" + resetUrl);
//         mailSender.send(message);
//     }

//     public void resetPassword(String token, String newPassword) {
//         Optional<PasswordResetToken> tokenOptional = tokenRepository.findByToken(token);
//         if (!tokenOptional.isPresent() || tokenOptional.get().getExpiryDate().before(new Date())) {
//             throw new IllegalArgumentException("Invalid or expired token");
//         }

//         PasswordResetToken resetToken = tokenOptional.get();
//         User user = userRepository.findByEmail(resetToken.getEmail())
//                 .orElseThrow(
//                         () -> new UsernameNotFoundException("User not found with email: " + resetToken.getEmail()));

//         user.setPassword(new BCryptPasswordEncoder().encode(newPassword));
//         userRepository.save(user);
//         tokenRepository.delete(resetToken); // Delete the token after successful reset
//     }
// }
