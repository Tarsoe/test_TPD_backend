//? This code for checking the userId
package com.example.matching.service;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.UUID;

public class CustomUserDetails implements UserDetails {

    private UUID userId;
    private String username;
    private String password;
    private final String email;
    private Collection<? extends GrantedAuthority> authorities;

    public CustomUserDetails(UUID userId, String username, String password, String email,
            Collection<? extends GrantedAuthority> authorities) {
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.email = email;
        this.authorities = authorities;
    }

    public UUID getUserId() {
        return userId;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}

// //? This code for checking the userId and still Long id
// package com.example.matching.service;

// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.userdetails.UserDetails;

// import java.util.Collection;

// public class CustomUserDetails implements UserDetails {

// private Long userId;
// private String username;
// private String password;
// private Collection<? extends GrantedAuthority> authorities;

// public CustomUserDetails(Long userId, String username, String password,
// Collection<? extends GrantedAuthority> authorities) {
// this.userId = userId;
// this.username = username;
// this.password = password;
// this.authorities = authorities;
// }

// public Long getUserId() {
// return userId;
// }

// @Override
// public String getUsername() {
// return username;
// }

// @Override
// public String getPassword() {
// return password;
// }

// @Override
// public Collection<? extends GrantedAuthority> getAuthorities() {
// return authorities;
// }

// @Override
// public boolean isAccountNonExpired() {
// return true;
// }

// @Override
// public boolean isAccountNonLocked() {
// return true;
// }

// @Override
// public boolean isCredentialsNonExpired() {
// return true;
// }

// @Override
// public boolean isEnabled() {
// return true;
// }
// }
