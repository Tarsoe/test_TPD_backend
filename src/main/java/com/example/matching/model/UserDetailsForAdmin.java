package com.example.matching.model;

public class UserDetailsForAdmin {
    private String username;
    private String email;

    public UserDetailsForAdmin(String username, String email) {
        this.username = username;
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    // @Override
    // public boolean equals(Object obj) {
    // if (this == obj)
    // return true;
    // if (obj == null || getClass() != obj.getClass())
    // return false;

    // UserDetailsForAdmin user = (UserDetailsForAdmin) obj;
    // return username.equals(user.username) || email.equals(user.email);
    // }

    // // @Override
    // // public int hashCode() {
    // // return username.hashCode(); // Simplified for the example
    // // }

    // @Override
    // public int hashCode() {
    // // Ensure username is not null
    // return username != null ? username.hashCode() : 0;
    // }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null || getClass() != obj.getClass())
            return false;

        UserDetailsForAdmin user = (UserDetailsForAdmin) obj;

        // Compare both username and email, allowing either to be the matching criterion
        if (this.username != null && user.username != null) {
            return username.equals(user.username);
        }
        if (this.email != null && user.email != null) {
            return email.equals(user.email);
        }
        return false;
    }

    @Override
    public int hashCode() {
        // Ensure neither username nor email is null for hashing
        int result = 17;
        result = 31 * result + (username != null ? username.hashCode() : 0);
        result = 31 * result + (email != null ? email.hashCode() : 0);
        return result;
    }
}
