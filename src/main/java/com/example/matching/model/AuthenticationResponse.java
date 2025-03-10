package com.example.matching.model;

import java.util.*;;

public class AuthenticationResponse {
    private final String token;
    private final String username;
    private final String email;
    private final UUID userId; // Add this line

    public AuthenticationResponse(String token, String username, String email, UUID userId) {
        this.token = token;
        this.username = username;
        this.email = email;
        this.userId = userId; // Add this line
    }

    // Getters
    public String getToken() {
        return token;
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

// ! End

// AuthenticationResponse.java
// package com.example.matching.model;

// public class AuthenticationResponse {

// private final String token;

// public AuthenticationResponse(String token) {
// this.token = token;
// }

// public String getToken() {
// return token;
// }
// // private final String jwt;

// // public AuthenticationResponse(String jwt) {
// // this.jwt = jwt;
// // }

// // public String getJwt() {
// // return jwt;
// // }
// }

// ! End

// package com.example.matching.model;

// public class AuthenticationResponse {

// private final String jwt;

// public AuthenticationResponse(String jwt) {
// this.jwt = jwt;
// }

// public String getJwt() {
// return jwt;
// }
// }
