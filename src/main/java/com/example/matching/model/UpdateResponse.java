package com.example.matching.model;

import java.util.*;

// Placeholder class for response including updated user
public class UpdateResponse {
    private String message;
    private final String username;
    private final String email;
    private final UUID userId;

    // Constructor, getters, and setters
    public UpdateResponse(String message, String username, String email, UUID userId) {
        this.message = message;
        this.username = username;
        this.email = email;
        this.userId = userId;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    public UUID getUserId() {
        return userId;
    }
}

//! Still Long ID
// package com.example.matching.model;

// // Placeholder class for response including updated user
// public class UpdateResponse {
//     private String message;
//     private final String username;
//     private final String email;
//     private final Long userId;

//     // Constructor, getters, and setters
//     public UpdateResponse(String message, String username, String email, Long userId) {
//         this.message = message;
//         this.username = username;
//         this.email = email;
//         this.userId = userId;
//     }

//     public String getMessage() {
//         return message;
//     }

//     public void setMessage(String message) {
//         this.message = message;
//     }

//     public String getUsername() {
//         return username;
//     }

//     public String getEmail() {
//         return email;
//     }

//     public Long getUserId() {
//         return userId;
//     }
// }

//! End
// package com.example.matching.model;

// // Placeholder class for response including updated user
// public class UpdateResponse {
// private String message;
// private User user;

// // Constructor, getters, and setters
// public UpdateResponse(String message, User user) {
// this.message = message;
// this.user = user;
// }

// public String getMessage() {
// return message;
// }

// public void setMessage(String message) {
// this.message = message;
// }

// public User getUser() {
// return user;
// }

// public void setUser(User user) {
// this.user = user;
// }
// }
