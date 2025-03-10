package com.example.matching.service;

import com.example.matching.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceForAdmin {

    @Autowired
    private JavaMailSender mailSender;

    public void sendAdminNotification(User user) {
        String adminEmail = "admln19939@gmail.com"; // Admin email address
        String subject = "User Account Locked: " + user.getUsername();
        String body = "Dear Admin,\n\n"
                + "The following user account has been locked due to multiple violations:\n\n"
                + "Username: " + user.getUsername() + "\n"
                + "Email: " + user.getEmail() + "\n"
                + "Please take the necessary actions.\n\n"
                + "Regards,\n"
                + "Your Application";

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(adminEmail);
        message.setSubject(subject);
        message.setText(body);

        mailSender.send(message);
        System.out.println("Email sent to admin regarding user lock.");
    }
}
