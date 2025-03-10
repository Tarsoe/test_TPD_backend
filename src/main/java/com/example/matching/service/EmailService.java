//! SMTP brevo
package com.example.matching.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {

    @Autowired
    private JavaMailSender mailSender;

    public void sendPasswordResetEmail(String to, String token) {
        String subject = "Password Reset Request";
        String message = "Click the link to reset your password: " + token;
        // String message = "Click the link to reset your password: https://your-app.com/reset?token=" + token;

        SimpleMailMessage email = new SimpleMailMessage();
        email.setTo(to);
        email.setSubject(subject);
        email.setText(message);
        email.setFrom("sheerlit639@gmail.com");
        // email.setFrom("your_verified_email@domain.com");

        mailSender.send(email);
    }
}

// ! Google SMTP
// package com.example.matching.service;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.mail.javamail.JavaMailSender;
// import org.springframework.mail.javamail.MimeMessageHelper;
// import org.springframework.stereotype.Service;

// import jakarta.mail.MessagingException;
// import jakarta.mail.internet.MimeMessage;

// // import javax.mail.MessagingException;
// // import javax.mail.internet.MimeMessage;

// @Service
// public class EmailService {

// @Autowired
// private JavaMailSender mailSender;

// public void sendPasswordResetEmail(String to, String token) {
// String subject = "Password Reset Request";
// // String text = "To reset your password, click the link below:\n"
// // + "http://localhost:8080/password-reset/validate?token=" + token;
// String text = "To reset your password, used this token below:\n" + token;

// try {
// MimeMessage message = mailSender.createMimeMessage();
// MimeMessageHelper helper = new MimeMessageHelper(message, true);
// helper.setTo(to);
// helper.setSubject(subject);
// helper.setText(text, true);
// mailSender.send(message);
// } catch (MessagingException e) {
// throw new RuntimeException("Failed to send email", e);
// }
// }
// }

// ! End

// package com.example.matching.service;

// import org.springframework.mail.javamail.JavaMailSender;
// import org.springframework.mail.javamail.MimeMessageHelper;
// import org.springframework.stereotype.Service;

// import jakarta.mail.MessagingException;
// import jakarta.mail.internet.MimeMessage;

// // import javax.mail.MessagingException;
// // import javax.mail.internet.MimeMessage;

// @Service
// public class EmailService {

// private final JavaMailSender mailSender;

// public EmailService(JavaMailSender mailSender) {
// this.mailSender = mailSender;
// }

// public void sendEmail(String to, String subject, String content) throws
// MessagingException {
// MimeMessage mimeMessage = mailSender.createMimeMessage();
// MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");
// helper.setText(content, true);
// helper.setTo(to);
// helper.setSubject(subject);
// helper.setFrom("noreply@yourdomain.com");
// mailSender.send(mimeMessage);
// }
// }
