//! with Rate Limiting Login Attempts
// package com.example.matching.model;

// import jakarta.persistence.*;
// import java.time.LocalDateTime;
// import java.util.Set;
// import java.util.UUID;

// @Entity
// @Table(name = "users_matching_UUID_1")
// public class User {

//     @Id
//     @GeneratedValue(strategy = GenerationType.AUTO)
//     @Column(name = "id", columnDefinition = "UUID")
//     private UUID id;

//     @Column(name = "email")
//     private String email;

//     @Column(name = "username")
//     private String username;

//     @Column(name = "password")
//     private String password;

//     @Column(name = "is_locked")
//     private boolean isLocked;

//     @Column(name = "violation_count")
//     private int violationCount;

//     @Column(name = "lock_until")
//     private LocalDateTime lockUntil;

//     @ElementCollection(fetch = FetchType.EAGER)
//     @CollectionTable(name = "user_roles_UUID", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id", columnDefinition = "UUID"))
//     @Column(name = "role")
//     private Set<String> roles;

//     // Getters and setters

//     public UUID getId() {
//         return id;
//     }

//     public void setId(UUID id) {
//         this.id = id;
//     }

//     public String getUsername() {
//         return username;
//     }

//     public void setUsername(String username) {
//         this.username = username;
//     }

//     public String getEmail() {
//         return email;
//     }

//     public void setEmail(String email) {
//         this.email = email;
//     }

//     public String getPassword() {
//         return password;
//     }

//     public void setPassword(String password) {
//         this.password = password;
//     }

//     public boolean isLocked() {
//         return isLocked;
//     }

//     public void setLocked(boolean locked) {
//         isLocked = locked;
//     }

//     public int getViolationCount() {
//         return violationCount;
//     }

//     public void setViolationCount(int violationCount) {
//         this.violationCount = violationCount;
//     }

//     public LocalDateTime getLockUntil() {
//         return lockUntil;
//     }

//     public void setLockUntil(LocalDateTime lockUntil) {
//         this.lockUntil = lockUntil;
//     }

//     public Set<String> getRoles() {
//         return roles;
//     }

//     public void setRoles(Set<String> roles) {
//         this.roles = roles;
//     }
// }

// ! without Rate Limiting Login Attempts
package com.example.matching.model;

import java.util.Set;
import java.util.UUID;

import jakarta.persistence.*;
import org.hibernate.annotations.GenericGenerator;

@Entity
@Table(name = "users_matching_UUID")
public class User {

    @Id
    @GeneratedValue
    @Column(name = "id", columnDefinition = "UUID")
    private UUID id;

    // private String username;
    // private String email;
    @Column(name = "email")
    private String email;

    @Column(name = "username")
    private String username;

    @Column(name = "password")
    private String password;

    // Define roles in a custom table
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles_UUID", // Custom table name
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id", columnDefinition = "UUID"))
    @Column(name = "role") // Column name for the role values
    private Set<String> roles;

    // ! No custom table name
    // @ElementCollection(fetch = FetchType.EAGER)
    // private Set<String> roles;

    // Getters and setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }
}

// ! with Rate Limiting Login Attempts
// package com.example.matching.model;

// import java.util.Set;
// import java.util.UUID;

// import jakarta.persistence.*;
// import org.hibernate.annotations.GenericGenerator;

// @Entity
// @Table(name = "users_matching_UUID_1")
// public class User {

// @Id
// @GeneratedValue
// @Column(name = "id", columnDefinition = "UUID")
// private UUID id;

// @Column(name = "email")
// private String email;

// @Column(name = "username")
// private String username;

// @Column(name = "password")
// private String password;

// // New fields for account locking
// @Column(name = "failed_login_attempts", nullable = false, columnDefinition =
// "int default 0")
// private int failedLoginAttempts = 0;

// @Column(name = "account_locked", nullable = false)
// private boolean accountLocked = false;

// @Column(name = "lock_time")
// private long lockTime;

// // Define roles in a custom table
// @ElementCollection(fetch = FetchType.EAGER)
// @CollectionTable(name = "user_roles_UUID", joinColumns = @JoinColumn(name =
// "user_id", referencedColumnName = "id", columnDefinition = "UUID"))
// @Column(name = "role")
// private Set<String> roles;

// // Getters and setters
// // ...
// public UUID getId() {
// return id;
// }

// public void setId(UUID id) {
// this.id = id;
// }

// public String getUsername() {
// return username;
// }

// public void setUsername(String username) {
// this.username = username;
// }

// public String getEmail() {
// return email;
// }

// public void setEmail(String email) {
// this.email = email;
// }

// public String getPassword() {
// return password;
// }

// public void setPassword(String password) {
// this.password = password;
// }

// public Set<String> getRoles() {
// return roles;
// }

// public void setRoles(Set<String> roles) {
// this.roles = roles;
// }

// public int getFailedLoginAttempts() {
// return failedLoginAttempts;
// }

// public void setFailedLoginAttempts(int failedLoginAttempts) {
// this.failedLoginAttempts = failedLoginAttempts;
// }

// public boolean isAccountLocked() {
// return accountLocked;
// }

// public void setAccountLocked(boolean accountLocked) {
// this.accountLocked = accountLocked;
// }

// public long getLockTime() {
// return lockTime;
// }

// public void setLockTime(long lockTime) {
// this.lockTime = lockTime;
// }
// }

// ! Change still LOng id
// package com.example.matching.model;

// import java.util.Set;

// import jakarta.persistence.*;

// @Entity
// @Table(name = "users_matching")
// public class User {
// @Id
// @GeneratedValue(strategy = GenerationType.IDENTITY)
// private Long id;

// private String username;
// private String email;
// private String password;

// @ElementCollection(fetch = FetchType.EAGER)
// private Set<String> roles;

// // Getters and setters
// public Long getId() {
// return id;
// }

// public void setId(Long id) {
// this.id = id;
// }

// public String getUsername() {
// return username;
// }

// public void setUsername(String username) {
// this.username = username;
// }

// public String getEmail() {
// return email;
// }

// public void setEmail(String email) {
// this.email = email;
// }

// public String getPassword() {
// return password;
// }

// public void setPassword(String password) {
// this.password = password;
// }

// public Set<String> getRoles() {
// return roles;
// }

// public void setRoles(Set<String> roles) {
// this.roles = roles;
// }
// }

// ! End
// package com.example.matching.model;

// import java.util.Set;

// import jakarta.persistence.*;

// @Entity
// @Table(name = "users_matching")
// public class User {
// @Id
// @GeneratedValue(strategy = GenerationType.IDENTITY)
// private Long id;

// private String username;
// private String email;
// private String password;

// @ElementCollection(fetch = FetchType.EAGER)
// private Set<String> roles;

// // Getters and setters
// public Long getId() {
// return id;
// }

// public void setId(Long id) {
// this.id = id;
// }

// public String getUsername() {
// return username;
// }

// public void setUsername(String username) {
// this.username = username;
// }

// public String getEmail() {
// return email;
// }

// public void setEmail(String email) {
// this.email = email;
// }

// public String getPassword() {
// return password;
// }

// public void setPassword(String password) {
// this.password = password;
// }

// public Set<String> getRoles() {
// return roles;
// }

// public void setRoles(Set<String> roles) {
// this.roles = roles;
// }
// }

// package com.example.matching.model;

// import jakarta.persistence.*;

// @Entity
// @Table(name = "users_matching")
// public class User {

// @Id
// @GeneratedValue(strategy = GenerationType.IDENTITY)
// private Long id;

// private String username;
// private String email;
// private String password;

// // Constructors, getters, and setters

// public Long getId() {
// return id;
// }

// public void setId(Long id) {
// this.id = id;
// }

// public String getUsername() {
// return username;
// }

// public void setUsername(String username) {
// this.username = username;
// }

// public String getEmail() {
// return email;
// }

// public void setEmail(String email) {
// this.email = email;
// }

// public String getPassword() {
// return password;
// }

// public void setPassword(String password) {
// this.password = password;
// }
// }

// package com.example.matching.model;

// import jakarta.persistence.*;

// @Entity
// @Table(name = "users_matching") // Specify the table name here
// public class User {

// @Id
// @GeneratedValue(strategy = GenerationType.IDENTITY)
// private Long id;

// private String username;
// private String email;
// private String password;

// // Constructors, getters, and setters
// // Omitted for brevity

// public Long getId() {
// return id;
// }

// public void setId(Long id) {
// this.id = id;
// }

// public String getUsername() {
// return username;
// }

// public void setUsername(String username) {
// this.username = username;
// }

// public String getEmail() {
// return email;
// }

// public void setEmail(String email) {
// this.email = email;
// }

// public String getPassword() {
// return password;
// }

// public void setPassword(String password) {
// this.password = password;
// }
// }

// package com.example.matching.model;

// import jakarta.persistence.*;

// // User.java

// @Entity
// public class User {

// @Id
// @GeneratedValue(strategy = GenerationType.IDENTITY)
// private Long id;

// private String username;
// private String email;
// private String password;

// // Constructors, getters, and setters

// public Long getId() {
// return id;
// }

// public void setId(Long id) {
// this.id = id;
// }

// public String getUsername() {
// return username;
// }

// public void setUsername(String username) {
// this.username = username;
// }

// public String getEmail() {
// return email;
// }

// public void setEmail(String email) {
// this.email = email;
// }

// public String getPassword() {
// return password;
// }

// public void setPassword(String password) {
// this.password = password;
// }
// }
