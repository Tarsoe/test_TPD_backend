//! Below is good and change to UUID
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
import java.util.*;

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

        throw new UsernameNotFoundException("User not found with username or email CustomUserDetailsService: "
                + usernameOrEmail);
    }

    public UserDetails loadUserById(UUID userId) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findById(userId);
        if (userOptional.isPresent()) {
            return createSpringSecurityUser(userOptional.get());
        }

        throw new UsernameNotFoundException("User not found with userId CustomUserDetailsService: " + userId);
    }

    private CustomUserDetails createSpringSecurityUser(User user) {
        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // return new CustomUserDetails(user.getId(), user.getUsername(), user.getPassword(), authorities);
        return new CustomUserDetails(user.getId(), user.getUsername(), user.getPassword(), user.getEmail(),authorities);
    }
}

//! End
// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;

// import java.util.ArrayList;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

//     @Autowired
//     private UserRepository userRepository;

//     @Override
//     public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
//         User user = userRepository.findByUsernameOrEmail(usernameOrEmail)
//                 .orElseThrow(() -> new UsernameNotFoundException(
//                         "User not found with username or email: " + usernameOrEmail));

//         return org.springframework.security.core.userdetails.User.builder()
//                 .username(user.getUsername())
//                 .password(user.getPassword())
//                 .authorities(new ArrayList<>()) // Add actual authorities/roles here if needed
//                 .build();
//     }
// }

// ! End

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
// return convertToUserDetails(user);
// }

// private UserDetails convertToUserDetails(User user) {
// return org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities("ROLE_USER") // Adjust roles as needed
// .build();
// }
// }

// ! End

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

// import java.util.Collections;
// import java.util.List;
// import java.util.Optional;
// import java.util.stream.Collectors;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// // @Override
// // public UserDetails loadUserByUsername(String usernameOrEmail) throws
// // UsernameNotFoundException {
// // Optional<User> userOptional =
// // userRepository.findByUsernameOrEmail(usernameOrEmail);
// // if (userOptional.isPresent()) {
// // return createSpringSecurityUser(userOptional.get());
// // }

// // throw new UsernameNotFoundException("User not found with username or
// email: "
// // + usernameOrEmail);
// // }
// // @Override
// // public UserDetails loadUserByUsername(String usernameOrEmail) throws
// // UsernameNotFoundException {
// // Optional<User> userOptional =
// // userRepository.findByUsernameOrEmail(usernameOrEmail);

// // return userOptional.map(user -> {
// // return new org.springframework.security.core.userdetails.User(
// // user.getUsername(),
// // user.getPassword(),
// // // Add any additional roles or authorities here if needed
// // Collections.emptyList());
// // }).orElseThrow(
// // () -> new UsernameNotFoundException("User not found with username or email
// // asdf: " + usernameOrEmail));
// // }
// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// Optional<User> userOptional =
// userRepository.findByUsernameOrEmail(usernameOrEmail);
// User user = userOptional.orElseThrow(() -> new UsernameNotFoundException(
// "User not found with username or email: " + usernameOrEmail));
// return convertToUserDetails(user);
// }

// private UserDetails convertToUserDetails(User user) {
// // Create and return a UserDetails object using the user information
// // For example:
// return org.springframework.security.core.userdetails.User.builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities("ROLE_USER") // Set authorities/roles as needed
// .build();
// }

// private org.springframework.security.core.userdetails.User
// createSpringSecurityUser(User user) {
// List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
// .map(SimpleGrantedAuthority::new)
// .collect(Collectors.toList());

// return (org.springframework.security.core.userdetails.User)
// org.springframework.security.core.userdetails.User
// .builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities(authorities)
// .build();
// }
// }

// ! End

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

// import java.util.ArrayList;
// import java.util.List;
// import java.util.Optional;
// import java.util.stream.Collectors;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

// @Autowired
// private UserRepository userRepository;

// // @Override
// // public UserDetails loadUserByUsername(String usernameOrEmail) throws
// // UsernameNotFoundException {
// // Optional<User> userOptional =
// userRepository.findByUsername(usernameOrEmail);
// // if (userOptional.isPresent()) {
// // return createSpringSecurityUser(userOptional.get());
// // }

// // userOptional = userRepository.findByEmail(usernameOrEmail);
// // if (userOptional.isPresent()) {
// // return createSpringSecurityUser(userOptional.get());
// // }

// // throw new UsernameNotFoundException("User not found with username or
// email: "
// // + usernameOrEmail);
// // }
// @Override
// public UserDetails loadUserByUsername(String usernameOrEmail) throws
// UsernameNotFoundException {
// User user = userRepository.findByUsernameOrEmail(usernameOrEmail)
// .orElseThrow(() -> new UsernameNotFoundException(
// "User not found with username or email test: " + usernameOrEmail));
// return new
// org.springframework.security.core.userdetails.User(user.getUsername(),
// user.getPassword(),
// new ArrayList<>());
// }

// private org.springframework.security.core.userdetails.User
// createSpringSecurityUser(User user) {
// List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
// .map(SimpleGrantedAuthority::new)
// .collect(Collectors.toList());

// return (org.springframework.security.core.userdetails.User)
// org.springframework.security.core.userdetails.User
// .builder()
// .username(user.getUsername())
// .password(user.getPassword())
// .authorities(authorities)
// .build();
// }
// }

// //! Below is good and still Long id
// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// import java.util.List;
// import java.util.Optional;
// import java.util.stream.Collectors;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

//     @Autowired
//     private UserRepository userRepository;

//     @Override
//     public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
//         Optional<User> userOptional = userRepository.findByUsername(usernameOrEmail);
//         if (userOptional.isPresent()) {
//             return createSpringSecurityUser(userOptional.get());
//         }

//         userOptional = userRepository.findByEmail(usernameOrEmail);
//         if (userOptional.isPresent()) {
//             return createSpringSecurityUser(userOptional.get());
//         }

//         throw new UsernameNotFoundException("User not found with username or email CustomUserDetailsService: "
//                 + usernameOrEmail);
//     }

//     public UserDetails loadUserById(Long userId) throws UsernameNotFoundException {
//         Optional<User> userOptional = userRepository.findById(userId);
//         if (userOptional.isPresent()) {
//             return createSpringSecurityUser(userOptional.get());
//         }

//         throw new UsernameNotFoundException("User not found with userId CustomUserDetailsService: " + userId);
//     }

//     private CustomUserDetails createSpringSecurityUser(User user) {
//         List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
//                 .map(SimpleGrantedAuthority::new)
//                 .collect(Collectors.toList());

//         return new CustomUserDetails(user.getId(), user.getUsername(), user.getPassword(), authorities);
//     }
// }



// ! End below code is good

// package com.example.matching.service;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.stereotype.Service;

// import java.util.List;
// import java.util.Optional;
// import java.util.stream.Collectors;

// @Service
// public class CustomUserDetailsService implements UserDetailsService {

//     @Autowired
//     private UserRepository userRepository;

//     @Override
//     public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
//         Optional<User> userOptional = userRepository.findByUsername(usernameOrEmail);
//         if (userOptional.isPresent()) {
//             return createSpringSecurityUser(userOptional.get());
//         }

//         userOptional = userRepository.findByEmail(usernameOrEmail);
//         if (userOptional.isPresent()) {
//             return createSpringSecurityUser(userOptional.get());
//         }

//         throw new UsernameNotFoundException("User not found with username or email CustomUserDetailsService: "
//                 + usernameOrEmail);
//     }

//     private org.springframework.security.core.userdetails.User createSpringSecurityUser(User user) {
//         List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
//                 .map(SimpleGrantedAuthority::new)
//                 .collect(Collectors.toList());

//         return (org.springframework.security.core.userdetails.User) org.springframework.security.core.userdetails.User
//                 .builder()
//                 .username(user.getUsername())
//                 .password(user.getPassword())
//                 .authorities(authorities)
//                 .build();
//     }
// }

// ! End

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
