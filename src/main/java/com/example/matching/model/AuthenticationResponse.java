package com.example.matching.model;

public class AuthenticationResponse {
    private final String token;
    private final String username;
    private final String email;

    public AuthenticationResponse(String token, String username, String email) {
        this.token = token;
        this.username = username;
        this.email = email;
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
