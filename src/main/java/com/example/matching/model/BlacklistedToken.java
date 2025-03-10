// BlacklistedToken.java
package com.example.matching.model;

import jakarta.persistence.*;

import java.util.*;

@Entity
@Table(name = "BlacklistedToken_matching_UUID")
public class BlacklistedToken {
    // @Id
    // @GeneratedValue(strategy = GenerationType.IDENTITY)
    // private Long id;
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id; 

    private String token;

    public BlacklistedToken() {
    }

    public BlacklistedToken(String token) {
        this.token = token;
    }

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}

//! Still Long id
// // BlacklistedToken.java
// package com.example.matching.model;

// import jakarta.persistence.*;

// // import javax.persistence.Entity;
// // import javax.persistence.GeneratedValue;
// // import javax.persistence.GenerationType;
// // import javax.persistence.Id;

// @Entity
// @Table(name = "BlacklistedToken_matching")
// public class BlacklistedToken {
//     @Id
//     @GeneratedValue(strategy = GenerationType.IDENTITY)
//     private Long id;

//     private String token;

//     public BlacklistedToken() {
//     }

//     public BlacklistedToken(String token) {
//         this.token = token;
//     }

//     public Long getId() {
//         return id;
//     }

//     public void setId(Long id) {
//         this.id = id;
//     }

//     public String getToken() {
//         return token;
//     }

//     public void setToken(String token) {
//         this.token = token;
//     }
// }
