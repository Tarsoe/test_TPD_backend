package com.example.matching.service;

import com.example.matching.model.User;
import com.example.matching.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByUsername(usernameOrEmail);
        if (userOptional.isPresent()) {
            return createSpringSecurityUser(userOptional.get());
        }

        userOptional = userRepository.findByEmail(usernameOrEmail);
        if (userOptional.isPresent()) {
            return createSpringSecurityUser(userOptional.get());
        }

        throw new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail);
    }

    private org.springframework.security.core.userdetails.User createSpringSecurityUser(User user) {
        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return (org.springframework.security.core.userdetails.User) org.springframework.security.core.userdetails.User
                .builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .authorities(authorities)
                .build();
    }
}

//! End

// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// import java.util.List;
// import java.util.Optional;
// import java.util.stream.Collectors;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// Optional<User> userOptional = userRepository.findByUsername(usernameOrEmail);
// if (userOptional.isPresent()) {
// return createSpringSecurityUser(userOptional.get());
// }

// userOptional = userRepository.findByEmail(usernameOrEmail);
// if (userOptional.isPresent()) {
// return createSpringSecurityUser(userOptional.get());
// }

// throw new UsernameNotFoundException("User not found with username or email: "
// + usernameOrEmail);
// }

// private org.springframework.security.core.userdetails.User
// createSpringSecurityUser(User user) {
// List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
// .map(SimpleGrantedAuthority::new)
// .collect(Collectors.toList());

// return (org.springframework.security.core.userdetails.User)
// org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities(authorities)
// .build();
// }
// }

// ! End here

// // CustomUserDetailsService.java
// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;

// import java.util.ArrayList;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String username) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsername(username);
// if (user == null) {
// throw new UsernameNotFoundException("User not found");
// }
// return new
// org.springframework.security.core.userdetails.User(user.getUsername(),
// user.getPassword(),
// new ArrayList<>());
// }
// }

// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsernameOrEmail(usernameOrEmail)
// .orElseThrow(() -> new UsernameNotFoundException(
// "User not found with username or email: " + usernameOrEmail));
// return org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// // .authorities(user.getRoles())
// .authorities(user.getRoles().toArray(new String[0]))
// .build();
// }

// public User loadUserEntityByUsername(String username) throws
// UsernameNotFoundException {
// return userRepository.findByUsername(username)
// .orElseThrow(() -> new UsernameNotFoundException("Username incorrect"));
// }

// public User loadUserEntityByEmail(String email) throws
// UsernameNotFoundException {
// return userRepository.findByEmail(email)
// .orElseThrow(() -> new UsernameNotFoundException("Email incorrect"));
// }
// }

// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsernameOrEmail(usernameOrEmail)
// // User user = userRepository.findByUsernameOrEmail(usernameOrEmail,
// usernameOrEmail)
// .orElseThrow(() -> new UsernameNotFoundException(
// "User not found with username or email: " + usernameOrEmail));
// return org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// // .authorities(user.getRoles())
// .authorities(user.getRoles().toArray(new String[0]))
// .build();
// }

// public User loadUserEntityByUsername(String username) throws
// UsernameNotFoundException {
// return userRepository.findByUsername(username)
// .orElseThrow(() -> new UsernameNotFoundException("Username incorrect"));
// }

// public User loadUserEntityByEmail(String email) throws
// UsernameNotFoundException {
// return userRepository.findByEmail(email)
// .orElseThrow(() -> new UsernameNotFoundException("Email incorrect"));
// }
// }

// package com.example.matching.service;

// import com.example.matching.exception.UserNotFoundException;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;
// // import org.springframework.security.core.userdetails.User;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsername(usernameOrEmail)
// .orElseGet(() -> userRepository.findByEmail(usernameOrEmail)
// .orElseThrow(
// () -> new UserNotFoundException("Username or Email not found: " +
// usernameOrEmail)));
// // return User.builder()
// // .username(user.getUsername())
// // .password(user.getPassword())
// // .authorities(user.getRoles())
// // .build();
// return org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities(user.getRoles().toArray(new String[0]))
// .build();
// }

// public User loadUserEntityByUsernameOrEmail(String usernameOrEmail) {
// return userRepository.findByUsername(usernameOrEmail)
// .orElseGet(() -> userRepository.findByEmail(usernameOrEmail)
// .orElseThrow(
// () -> new UserNotFoundException("Username or Email not found: " +
// usernameOrEmail)));

// }
// }

// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsernameOrEmail(usernameOrEmail)
// .orElseThrow(() -> new UsernameNotFoundException(
// "User not found with username or email: " + usernameOrEmail));
// return org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities(user.getRoles().toArray(new String[0]))
// .build();
// }
// }

// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsernameOrEmail(usernameOrEmail,
// usernameOrEmail)
// .orElseThrow(() -> new UsernameNotFoundException(
// "User not found with username or email: " + usernameOrEmail));
// return org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities(user.getRoles())
// .build();
// }
// }

// // CustomUserDetailsService.java
// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;

// import java.util.ArrayList;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// @Override
// public UserDetails loadUserByUsername(String username) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsername(username);
// if (user == null) {
// throw new UsernameNotFoundException("User not found");
// }
// return new
// org.springframework.security.core.userdetails.User(user.getUsername(),
// user.getPassword(),
// new ArrayList<>());
// }
// }
