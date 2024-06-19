package com.example.matching.model;

import java.util.Date;
import jakarta.persistence.*;

@Entity
@Table(name = "PasswordResetToken")
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String token;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    private Date expiryDate;

    public PasswordResetToken() {
    }

    public PasswordResetToken(String token, User user) {
        this.token = token;
        this.user = user;
    }

    // Getters and setters

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }
}


// ! End

// package com.example.matching.model;

// import jakarta.persistence.*;
// import java.util.Date;

// @Entity
// @Table(name = "PasswordResetToken")
// public class PasswordResetToken {

// @Id
// @GeneratedValue(strategy = GenerationType.IDENTITY)
// private Long id;

// @Column(nullable = false, unique = true)
// private String token;

// @Column(nullable = false)
// private String email;

// @Column(nullable = false)
// @Temporal(TemporalType.TIMESTAMP)
// private Date expiryDate;

// public PasswordResetToken() {
// }

// public PasswordResetToken(String token, String email, Date expiryDate) {
// this.token = token;
// this.email = email;
// this.expiryDate = expiryDate;
// }

// // Getters and setters
// public Long getId() {
// return id;
// }

// public void setId(Long id) {
// this.id = id;
// }

// public String getToken() {
// return token;
// }

// public void setToken(String token) {
// this.token = token;
// }

// public String getEmail() {
// return email;
// }

// public void setEmail(String email) {
// this.email = email;
// }

// public Date getExpiryDate() {
// return expiryDate;
// }

// public void setExpiryDate(Date expiryDate) {
// this.expiryDate = expiryDate;
// }
// }

// ! End

// package com.example.matching.model;

// import java.time.LocalDateTime;
// import java.time.temporal.ChronoUnit;

// import jakarta.persistence.*;

// @Entity
// @Table(name = "PasswordResetToken")
// public class PasswordResetToken {

// private static final int EXPIRATION_MINUTES = 60; // Token expiration time in
// minutes

// @Id
// @GeneratedValue(strategy = GenerationType.IDENTITY)
// private Long id;

// private String token;

// @OneToOne(targetEntity = User.class, fetch = FetchType.EAGER)
// @JoinColumn(nullable = false, name = "user_id")
// private User user;

// private LocalDateTime expiryDate;

// public PasswordResetToken() {
// }

// public PasswordResetToken(User user, String token) {
// this.user = user;
// this.token = token;
// this.expiryDate = calculateExpiryDate(EXPIRATION_MINUTES);
// }

// private LocalDateTime calculateExpiryDate(int expiryTimeInMinutes) {
// return LocalDateTime.now().plus(expiryTimeInMinutes, ChronoUnit.MINUTES);
// }

// public Long getId() {
// return id;
// }

// public void setId(Long id) {
// this.id = id;
// }

// public String getToken() {
// return token;
// }

// public void setToken(String token) {
// this.token = token;
// }

// public User getUser() {
// return user;
// }

// public void setUser(User user) {
// this.user = user;
// }

// public LocalDateTime getExpiryDate() {
// return expiryDate;
// }

// public void setExpiryDate(LocalDateTime expiryDate) {
// this.expiryDate = expiryDate;
// }

// public boolean isExpired() {
// return LocalDateTime.now().isAfter(this.expiryDate);
// }
// }
