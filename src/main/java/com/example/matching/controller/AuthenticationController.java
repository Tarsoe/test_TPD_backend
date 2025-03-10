package com.example.matching.controller;

import com.example.matching.exception.ForbiddenException;
import com.example.matching.exception.UnauthorizedException;
import com.example.matching.model.AuthenticationRequest;
import com.example.matching.model.AuthenticationResponse;
import com.example.matching.model.UpdateResponse;
import com.example.matching.model.User;
import com.example.matching.repository.UserRepository;
import com.example.matching.service.CustomUserDetails;
import com.example.matching.service.CustomUserDetailsService;
import com.example.matching.util.JwtTokenUtil;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@RestController
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/authenticate")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest,
            HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
                            authenticationRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
            User user = userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
                    .orElseThrow(() -> new BadCredentialsException(
                            "User not found with username or email: " +
                                    authenticationRequest.getUsernameOrEmail()));

            String jwt = jwtTokenUtil.generateToken(userDetails, user.getId());

            // Store JWT in HttpOnly cookie
            Cookie cookie = new Cookie("jwtToken", jwt);
            cookie.setHttpOnly(true);
            cookie.setSecure(true); // Ensure this is set to true in production (HTTPS only)
            cookie.setMaxAge(3600); // Expire after 1 hour
            cookie.setPath("/");

            // Add cookie to response
            response.addCookie(cookie);

            // Manually add SameSite attribute to Set-Cookie header
            response.setHeader("Set-Cookie",
                    String.format("jwtToken=%s; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Strict", jwt));

            return ResponseEntity.ok(new AuthenticationResponse("", user.getUsername(),
                    user.getEmail(), user.getId()));
        } catch (BadCredentialsException e) {
            return handleBadCredentialsException(authenticationRequest);
        }
    }

    private ResponseEntity<String> handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
        Optional<User> userOptional = userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
        if (userOptional.isPresent()) {
            return ResponseEntity.badRequest().body("Your input password is not correct");
        }

        userOptional = userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
        if (userOptional.isPresent()) {
            return ResponseEntity.badRequest().body("Your input password is not correct");
        }

        userOptional = userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
        if (userOptional.isPresent()) {
            return ResponseEntity.badRequest().body("Your input username is not correct");
        }

        if (authenticationRequest.getUsernameOrEmail().contains("@")) {
            return ResponseEntity.badRequest().body("You input email incorrect");
        } else {
            return ResponseEntity.badRequest().body("Input username incorrect");
        }
    }

    @PutMapping("/user/{id}")
    public ResponseEntity<?> updateUser(@PathVariable UUID id, @RequestBody User updatedUser) {
        System.out.println("Enter the  @PutMapping(\"/user/{id}\")");
        // Check authentication
        if (!isAuthenticated()) {
            throw new UnauthorizedException("You are not authorized to perform this operation.");
        }

        // Check update permission
        if (!hasUpdatePermission(id)) {
            throw new ForbiddenException("You are not allowed to update this user.");
        }

        Optional<User> userOptional = userRepository.findById(id);
        if (userOptional.isEmpty()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        User user = userOptional.get();

        boolean usernameChanged = !user.getUsername().equals(updatedUser.getUsername());
        boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

        user.setUsername(updatedUser.getUsername());
        user.setEmail(updatedUser.getEmail());
        userRepository.save(user);

        String responseMessage;
        if (usernameChanged && emailChanged) {
            System.out.println("Enter  if (usernameChanged && emailChanged)");
            responseMessage = "Username and email updated successfully.";
        } else if (usernameChanged) {
            System.out.println("Enter  } else if (usernameChanged) {");
            responseMessage = "Username updated successfully.";
        } else if (emailChanged) {
            responseMessage = "Email updated successfully.";
        } else {
            responseMessage = "No changes detected.";
        }
        return ResponseEntity.ok()
                .body(new UpdateResponse(responseMessage, user.getUsername(), user.getEmail(), user.getId()));
    }

    // Placeholder for authentication check
    private boolean isAuthenticated() {
        // Implement your authentication logic here
        return true; // Placeholder
    }

    // Placeholder for permission check
    private boolean hasUpdatePermission(UUID id) {
        // Implement your permission check logic here
        return true; // Placeholder
    }

    @DeleteMapping("/user/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable UUID id) {
        Optional<User> userOptional = userRepository.findById(id);
        if (userOptional.isPresent()) {
            userRepository.delete(userOptional.get());
            return ResponseEntity.ok("User deleted successfully");
        } else {
            return ResponseEntity.badRequest().body("User not found");
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(HttpServletRequest request) {
        String authorizationHeader = request.getHeader("Authorization");

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String oldToken = authorizationHeader.substring(7);

            try {
                // Validate the old token
                UUID userId = jwtTokenUtil.getUserIdFromToken(oldToken);
                UserDetails userDetails = userDetailsService.loadUserById(userId);

                if (jwtTokenUtil.isTokenAboutToExpire(oldToken, 15)) { // Threshold 15 minutes
                    String newToken = jwtTokenUtil.generateToken(userDetails, userId);
                    // return ResponseEntity.ok(new AuthenticationResponse(newToken,
                    // userDetails.getUsername(), userId));
                    return ResponseEntity.ok(new AuthenticationResponse(newToken, userDetails.getUsername(),
                            ((CustomUserDetails) userDetails).getEmail(), userId));

                } else {
                    return ResponseEntity.badRequest().body("Token is not close to expiration");
                }
            } catch (ExpiredJwtException e) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token has expired, cannot refresh");
            }
        }

        return ResponseEntity.badRequest().body("Invalid token format");
    }

}

// //! With Rate Limit Login
// package com.example.matching.controller;

// import com.example.matching.exception.ForbiddenException;
// import com.example.matching.exception.UnauthorizedException;
// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.UpdateResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetails;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import jakarta.servlet.http.Cookie;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.access.prepost.PreAuthorize;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.web.bind.annotation.*;

// import org.springframework.transaction.annotation.Transactional;

// import java.util.*;

// @RestController
// public class AuthenticationController {

//     @Autowired
//     private AuthenticationManager authenticationManager;

//     @Autowired
//     private CustomUserDetailsService userDetailsService;

//     @Autowired
//     private JwtTokenUtil jwtTokenUtil;

//     @Autowired
//     private UserRepository userRepository;

//     @PostMapping("/authenticate")
//     public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest,
//             HttpServletResponse response) {
//         try {
//             Authentication authentication = authenticationManager.authenticate(
//                     new UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
//                             authenticationRequest.getPassword()));

//             SecurityContextHolder.getContext().setAuthentication(authentication);

//             UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
//             User user = userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
//                     .orElseThrow(() -> new BadCredentialsException(
//                             "User not found with username or email: " +
//                                     authenticationRequest.getUsernameOrEmail()));

//             String jwt = jwtTokenUtil.generateToken(userDetails, user.getId());

//             // Store JWT in HttpOnly cookie
//             Cookie cookie = new Cookie("jwtToken", jwt);
//             cookie.setHttpOnly(true);
//             cookie.setSecure(true); // Ensure this is set to true in production (HTTPS only)
//             cookie.setMaxAge(3600); // Expire after 1 hour
//             cookie.setPath("/");

//             // Add cookie to response
//             response.addCookie(cookie);

//             // Manually add SameSite attribute to Set-Cookie header
//             response.setHeader("Set-Cookie",
//                     String.format("jwtToken=%s; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Strict", jwt));

//             return ResponseEntity.ok(new AuthenticationResponse("", user.getUsername(),
//                     user.getEmail(), user.getId()));
//         } catch (BadCredentialsException e) {
//             return handleBadCredentialsException(authenticationRequest);
//         }
//     }

//     // @Transactional
//     // @PostMapping("/authenticate")
//     // public ResponseEntity<?> createAuthenticationToken(@RequestBody
//     // AuthenticationRequest authenticationRequest,
//     // HttpServletResponse response) {
//     // try {
//     // Optional<User> userOptional = userRepository
//     // .findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail());

//     // if (userOptional.isEmpty()) {
//     // // return ResponseEntity.badRequest().body("User not found. 1");
//     // return handleBadCredentialsException(authenticationRequest);
//     // }

//     // User user = userOptional.get();

//     // // Check if the account is locked
//     // if (user.isAccountLocked() && (System.currentTimeMillis() <
//     // user.getLockTime() + (5 * 60 * 1000))) {
//     // return ResponseEntity.badRequest()
//     // .body("Your account is locked. Please wait 5 minutes or contact
//     // admin19939@gmail.com.");
//     // }

//     // Authentication authentication = authenticationManager.authenticate(
//     // new
//     // UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
//     // authenticationRequest.getPassword()));

//     // SecurityContextHolder.getContext().setAuthentication(authentication);

//     // // Reset failed attempts on successful login
//     // userRepository.resetFailedLoginAttempts(user.getId());

//     // // Generate token and set cookie (existing code)
//     // // ...

//     // UserDetails userDetails =
//     // userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
//     // // User user =
//     // //
//     // userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
//     // user =
//     // userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
//     // .orElseThrow(() -> new BadCredentialsException(
//     // "User not found with username or email: " +
//     // authenticationRequest.getUsernameOrEmail()));

//     // String jwt = jwtTokenUtil.generateToken(userDetails, user.getId());

//     // // Store JWT in HttpOnly cookie
//     // Cookie cookie = new Cookie("jwtToken", jwt);
//     // cookie.setHttpOnly(true);
//     // cookie.setSecure(true); // Ensure this is set to true in production (HTTPS
//     // only)
//     // cookie.setMaxAge(3600); // Expire after 1 hour
//     // cookie.setPath("/");

//     // // Add cookie to response
//     // response.addCookie(cookie);

//     // // Manually add SameSite attribute to Set-Cookie header
//     // response.setHeader("Set-Cookie",
//     // String.format("jwtToken=%s; Path=/; HttpOnly; Secure; Max-Age=3600;
//     // SameSite=Strict", jwt));

//     // return ResponseEntity.ok(new AuthenticationResponse("", user.getUsername(),
//     // user.getEmail(), user.getId()));

//     // // return ResponseEntity.ok("Authenticated successfully");

//     // } catch (BadCredentialsException e) {
//     // // Call the handleLoginFailure method to handle failed login attempts
//     // handleLoginFailure(authenticationRequest);
//     // // Handle the bad credentials response by calling
//     // handleBadCredentialsException
//     // return handleBadCredentialsException(authenticationRequest);
//     // }
//     // }

//     // private void handleLoginFailure(AuthenticationRequest authenticationRequest)
//     // {
//     // Optional<User> userOptional =
//     // userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail());

//     // if (userOptional.isPresent()) {
//     // User user = userOptional.get();

//     // // Increment failed login attempts
//     // user.setFailedLoginAttempts(user.getFailedLoginAttempts() + 1);

//     // // Check if the maximum number of attempts is reached
//     // if (user.getFailedLoginAttempts() >= 5) {
//     // user.setAccountLocked(true);
//     // user.setLockTime(System.currentTimeMillis());
//     // // userRepository.lockUserAccount(user.getId(), true, user.getLockTime());
//     // userRepository.lockUserAccount(user.getId(), user.getLockTime());

//     // // Optionally, send a notification email to the admin or user
//     // } else {
//     // userRepository.updateFailedLoginAttempts(user.getId(),
//     // user.getFailedLoginAttempts());
//     // }

//     // ResponseEntity.badRequest()
//     // .body("Invalid credentials. Attempt " + user.getFailedLoginAttempts() + " of
//     // 5.");
//     // } else {
//     // ResponseEntity.badRequest().body("User not found. 2");
//     // }
//     // }

//     private ResponseEntity<String> handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
//         Optional<User> userOptional = userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
//         if (userOptional.isPresent()) {
//             return ResponseEntity.badRequest().body("Your input password is not correct");
//         }

//         userOptional = userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
//         if (userOptional.isPresent()) {
//             return ResponseEntity.badRequest().body("Your input password is not correct");
//         }

//         userOptional = userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
//         if (userOptional.isPresent()) {
//             return ResponseEntity.badRequest().body("Your input username is not correct");
//         }

//         if (authenticationRequest.getUsernameOrEmail().contains("@")) {
//             return ResponseEntity.badRequest().body("You input email incorrect");
//         } else {
//             return ResponseEntity.badRequest().body("Input username incorrect");
//         }
//     }

//     @PutMapping("/user/{id}")
//     public ResponseEntity<?> updateUser(@PathVariable UUID id, @RequestBody User updatedUser) {
//         System.out.println("Enter the  @PutMapping(\"/user/{id}\")");
//         // Check authentication
//         if (!isAuthenticated()) {
//             throw new UnauthorizedException("You are not authorized to perform this operation.");
//         }

//         // Check update permission
//         if (!hasUpdatePermission(id)) {
//             throw new ForbiddenException("You are not allowed to update this user.");
//         }

//         Optional<User> userOptional = userRepository.findById(id);
//         if (userOptional.isEmpty()) {
//             return ResponseEntity.badRequest().body("User not found");
//         }

//         User user = userOptional.get();

//         boolean usernameChanged = !user.getUsername().equals(updatedUser.getUsername());
//         boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

//         user.setUsername(updatedUser.getUsername());
//         user.setEmail(updatedUser.getEmail());
//         userRepository.save(user);

//         String responseMessage;
//         if (usernameChanged && emailChanged) {
//             System.out.println("Enter  if (usernameChanged && emailChanged)");
//             responseMessage = "Username and email updated successfully.";
//         } else if (usernameChanged) {
//             System.out.println("Enter  } else if (usernameChanged) {");
//             responseMessage = "Username updated successfully.";
//         } else if (emailChanged) {
//             responseMessage = "Email updated successfully.";
//         } else {
//             responseMessage = "No changes detected.";
//         }
//         return ResponseEntity.ok()
//                 .body(new UpdateResponse(responseMessage, user.getUsername(), user.getEmail(), user.getId()));
//     }

//     // Placeholder for authentication check
//     private boolean isAuthenticated() {
//         // Implement your authentication logic here
//         return true; // Placeholder
//     }

//     // Placeholder for permission check
//     private boolean hasUpdatePermission(UUID id) {
//         // Implement your permission check logic here
//         return true; // Placeholder
//     }

//     @DeleteMapping("/user/{id}")
//     public ResponseEntity<?> deleteUser(@PathVariable UUID id) {
//         Optional<User> userOptional = userRepository.findById(id);
//         if (userOptional.isPresent()) {
//             userRepository.delete(userOptional.get());
//             return ResponseEntity.ok("User deleted successfully");
//         } else {
//             return ResponseEntity.badRequest().body("User not found");
//         }
//     }

//     @PostMapping("/refresh-token")
//     public ResponseEntity<?> refreshToken(HttpServletRequest request) {
//         String authorizationHeader = request.getHeader("Authorization");

//         if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
//             String oldToken = authorizationHeader.substring(7);

//             try {
//                 // Validate the old token
//                 UUID userId = jwtTokenUtil.getUserIdFromToken(oldToken);
//                 UserDetails userDetails = userDetailsService.loadUserById(userId);

//                 if (jwtTokenUtil.isTokenAboutToExpire(oldToken, 15)) { // Threshold 15 minutes
//                     String newToken = jwtTokenUtil.generateToken(userDetails, userId);
//                     // return ResponseEntity.ok(new AuthenticationResponse(newToken,
//                     // userDetails.getUsername(), userId));
//                     return ResponseEntity.ok(new AuthenticationResponse(newToken, userDetails.getUsername(),
//                             ((CustomUserDetails) userDetails).getEmail(), userId));

//                 } else {
//                     return ResponseEntity.badRequest().body("Token is not close to expiration");
//                 }
//             } catch (ExpiredJwtException e) {
//                 return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token has expired, cannot refresh");
//             }
//         }

//         return ResponseEntity.badRequest().body("Invalid token format");
//     }

// }

// ! with comments
// package com.example.matching.controller;

// import com.example.matching.exception.ForbiddenException;
// import com.example.matching.exception.UnauthorizedException;
// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.UpdateResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetails;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import jakarta.servlet.http.Cookie;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.access.prepost.PreAuthorize;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.web.bind.annotation.*;

// import java.util.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private UserRepository userRepository;

// // @PostMapping("/authenticate")
// // public ResponseEntity<?> createAuthenticationToken(@RequestBody
// // AuthenticationRequest authenticationRequest) {
// // try {
// // Authentication authentication = authenticationManager.authenticate(
// // new
// //
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// // authenticationRequest.getPassword()));

// // SecurityContextHolder.getContext().setAuthentication(authentication);

// // UserDetails userDetails =
// //
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// // User user =
// //
// userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
// // .orElseThrow(() -> new BadCredentialsException(
// // "User not found with username or email: " +
// // authenticationRequest.getUsernameOrEmail()));

// // // String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail(),
// // // user.getId().toString());
// // // ! Good
// // // String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail(),
// // // user.getId());

// // // ? Generate token for user with only userId
// // String jwt = jwtTokenUtil.generateToken(userDetails, user.getId());

// // return ResponseEntity
// // .ok(new AuthenticationResponse(jwt, user.getUsername(), user.getEmail(),
// // user.getId()));
// // } catch (BadCredentialsException e) {
// // return handleBadCredentialsException(authenticationRequest);
// // }
// // }
// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest,
// HttpServletResponse response) {
// try {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// User user =
// userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
// .orElseThrow(() -> new BadCredentialsException(
// "User not found with username or email: " +
// authenticationRequest.getUsernameOrEmail()));

// String jwt = jwtTokenUtil.generateToken(userDetails, user.getId());

// // Store JWT in HttpOnly cookie
// // Cookie cookie = new Cookie("jwtToken", jwt);
// // cookie.setHttpOnly(true);
// // cookie.setSecure(true); // Ensure this is set to true in production (HTTPS
// // only)
// // cookie.setMaxAge(3600); // Expire after 1 hour
// // cookie.setPath("/");
// // cookie.setSameSite("Strict"); // Can be Lax or Strict, depending on the
// app
// // requirements

// // response.addCookie(cookie);

// // Store JWT in HttpOnly cookie
// Cookie cookie = new Cookie("jwtToken", jwt);
// cookie.setHttpOnly(true);
// cookie.setSecure(true); // Ensure this is set to true in production (HTTPS
// only)
// cookie.setMaxAge(3600); // Expire after 1 hour
// cookie.setPath("/");

// // Add cookie to response
// response.addCookie(cookie);

// // Manually add SameSite attribute to Set-Cookie header
// response.setHeader("Set-Cookie",
// String.format("jwtToken=%s; Path=/; HttpOnly; Secure; Max-Age=3600;
// SameSite=Strict", jwt));

// return ResponseEntity.ok(new AuthenticationResponse("", user.getUsername(),
// user.getEmail(), user.getId()));
// } catch (BadCredentialsException e) {
// return handleBadCredentialsException(authenticationRequest);
// }
// }

// private ResponseEntity<String>
// handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
// Optional<User> userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input username is not
// correct");
// }

// if (authenticationRequest.getUsernameOrEmail().contains("@")) {
// return ResponseEntity.badRequest().body("You input email incorrect");
// } else {
// return ResponseEntity.badRequest().body("Input username incorrect");
// }
// }

// @PutMapping("/user/{id}")
// public ResponseEntity<?> updateUser(@PathVariable UUID id, @RequestBody User
// updatedUser) {
// System.out.println("Enter the @PutMapping(\"/user/{id}\")");
// // Check authentication
// if (!isAuthenticated()) {
// throw new UnauthorizedException("You are not authorized to perform this
// operation.");
// }

// // Check update permission
// if (!hasUpdatePermission(id)) {
// throw new ForbiddenException("You are not allowed to update this user.");
// }

// Optional<User> userOptional = userRepository.findById(id);
// if (userOptional.isEmpty()) {
// return ResponseEntity.badRequest().body("User not found");
// }

// User user = userOptional.get();

// boolean usernameChanged =
// !user.getUsername().equals(updatedUser.getUsername());
// boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

// user.setUsername(updatedUser.getUsername());
// user.setEmail(updatedUser.getEmail());
// userRepository.save(user);

// String responseMessage;
// if (usernameChanged && emailChanged) {
// System.out.println("Enter if (usernameChanged && emailChanged)");
// responseMessage = "Username and email updated successfully.";
// } else if (usernameChanged) {
// System.out.println("Enter } else if (usernameChanged) {");
// responseMessage = "Username updated successfully.";
// } else if (emailChanged) {
// responseMessage = "Email updated successfully.";
// } else {
// responseMessage = "No changes detected.";
// }
// return ResponseEntity.ok()
// .body(new UpdateResponse(responseMessage, user.getUsername(),
// user.getEmail(), user.getId()));
// }

// // Placeholder for authentication check
// private boolean isAuthenticated() {
// // Implement your authentication logic here
// return true; // Placeholder
// }

// // Placeholder for permission check
// private boolean hasUpdatePermission(UUID id) {
// // Implement your permission check logic here
// return true; // Placeholder
// }

// @DeleteMapping("/user/{id}")
// public ResponseEntity<?> deleteUser(@PathVariable UUID id) {
// Optional<User> userOptional = userRepository.findById(id);
// if (userOptional.isPresent()) {
// userRepository.delete(userOptional.get());
// return ResponseEntity.ok("User deleted successfully");
// } else {
// return ResponseEntity.badRequest().body("User not found");
// }
// }

// @PostMapping("/refresh-token")
// public ResponseEntity<?> refreshToken(HttpServletRequest request) {
// String authorizationHeader = request.getHeader("Authorization");

// if (authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
// {
// String oldToken = authorizationHeader.substring(7);

// try {
// // Validate the old token
// UUID userId = jwtTokenUtil.getUserIdFromToken(oldToken);
// UserDetails userDetails = userDetailsService.loadUserById(userId);

// if (jwtTokenUtil.isTokenAboutToExpire(oldToken, 15)) { // Threshold 15
// minutes
// String newToken = jwtTokenUtil.generateToken(userDetails, userId);
// // return ResponseEntity.ok(new AuthenticationResponse(newToken,
// // userDetails.getUsername(), userId));
// return ResponseEntity.ok(new AuthenticationResponse(newToken,
// userDetails.getUsername(),
// ((CustomUserDetails) userDetails).getEmail(), userId));

// } else {
// return ResponseEntity.badRequest().body("Token is not close to expiration");
// }
// } catch (ExpiredJwtException e) {
// return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token has
// expired, cannot refresh");
// }
// }

// return ResponseEntity.badRequest().body("Invalid token format");
// }

// }

// ! Still long id
// package com.example.matching.controller;

// import com.example.matching.exception.ForbiddenException;
// import com.example.matching.exception.UnauthorizedException;
// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.UpdateResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.access.prepost.PreAuthorize;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.web.bind.annotation.*;

// import java.util.Optional;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private UserRepository userRepository;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest) {
// try {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// User user =
// userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
// .orElseThrow(() -> new BadCredentialsException(
// "User not found with username or email: " +
// authenticationRequest.getUsernameOrEmail()));

// // String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail(),
// user.getId().toString());
// String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail(),
// user.getId());

// return ResponseEntity
// .ok(new AuthenticationResponse(jwt, user.getUsername(), user.getEmail(),
// user.getId()));
// } catch (BadCredentialsException e) {
// return handleBadCredentialsException(authenticationRequest);
// }
// }

// private ResponseEntity<String>
// handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
// Optional<User> userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input username is not
// correct");
// }

// if (authenticationRequest.getUsernameOrEmail().contains("@")) {
// return ResponseEntity.badRequest().body("You input email incorrect");
// } else {
// return ResponseEntity.badRequest().body("Input username incorrect");
// }
// }

// @PutMapping("/user/{id}")
// public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User
// updatedUser) {
// System.out.println("Enter the @PutMapping(\"/user/{id}\")");
// // Check authentication
// if (!isAuthenticated()) {
// throw new UnauthorizedException("You are not authorized to perform this
// operation.");
// }

// // Check update permission
// if (!hasUpdatePermission(id)) {
// throw new ForbiddenException("You are not allowed to update this user.");
// }

// Optional<User> userOptional = userRepository.findById(id);
// if (userOptional.isEmpty()) {
// return ResponseEntity.badRequest().body("User not found");
// }

// User user = userOptional.get();

// boolean usernameChanged =
// !user.getUsername().equals(updatedUser.getUsername());
// boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

// user.setUsername(updatedUser.getUsername());
// user.setEmail(updatedUser.getEmail());
// userRepository.save(user);

// String responseMessage;
// if (usernameChanged && emailChanged) {
// System.out.println("Enter if (usernameChanged && emailChanged)");
// responseMessage = "Username and email updated successfully.";
// } else if (usernameChanged) {
// System.out.println("Enter } else if (usernameChanged) {");
// responseMessage = "Username updated successfully.";
// } else if (emailChanged) {
// responseMessage = "Email updated successfully.";
// } else {
// responseMessage = "No changes detected.";
// }
// return ResponseEntity.ok()
// .body(new UpdateResponse(responseMessage, user.getUsername(),
// user.getEmail(), user.getId()));
// }

// // Placeholder for authentication check
// private boolean isAuthenticated() {
// // Implement your authentication logic here
// return true; // Placeholder
// }

// // Placeholder for permission check
// private boolean hasUpdatePermission(Long id) {
// // Implement your permission check logic here
// return true; // Placeholder
// }

// @DeleteMapping("/user/{id}")
// public ResponseEntity<?> deleteUser(@PathVariable Long id) {
// Optional<User> userOptional = userRepository.findById(id);
// if (userOptional.isPresent()) {
// userRepository.delete(userOptional.get());
// return ResponseEntity.ok("User deleted successfully");
// } else {
// return ResponseEntity.badRequest().body("User not found");
// }
// }

// }

// ! Below code is good
// package com.example.matching.controller;

// import com.example.matching.exception.ForbiddenException;
// import com.example.matching.exception.UnauthorizedException;
// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.UpdateResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.access.prepost.PreAuthorize;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.web.bind.annotation.*;

// import java.util.Optional;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private UserRepository userRepository;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest) {
// try {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// User user =
// userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
// .orElseThrow(() -> new BadCredentialsException(
// "User not found with username or email: " +
// authenticationRequest.getUsernameOrEmail()));

// // String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail(),
// user.getId().toString());
// String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail(),
// user.getId());

// return ResponseEntity
// .ok(new AuthenticationResponse(jwt, user.getUsername(), user.getEmail(),
// user.getId()));
// } catch (BadCredentialsException e) {
// return handleBadCredentialsException(authenticationRequest);
// }
// }

// private ResponseEntity<String>
// handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
// Optional<User> userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// if (authenticationRequest.getUsernameOrEmail().contains("@")) {
// return ResponseEntity.badRequest().body("You input email incorrect");
// } else {
// return ResponseEntity.badRequest().body("Input username incorrect");
// }
// }

// @PutMapping("/user/{id}")
// public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User
// updatedUser) {
// System.out.println("Enter the @PutMapping(\"/user/{id}\")");
// // Check authentication
// if (!isAuthenticated()) {
// throw new UnauthorizedException("You are not authorized to perform this
// operation.");
// }

// // Check update permission
// if (!hasUpdatePermission(id)) {
// throw new ForbiddenException("You are not allowed to update this user.");
// }

// Optional<User> userOptional = userRepository.findById(id);
// if (userOptional.isEmpty()) {
// return ResponseEntity.badRequest().body("User not found");
// }

// User user = userOptional.get();

// boolean usernameChanged =
// !user.getUsername().equals(updatedUser.getUsername());
// boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

// user.setUsername(updatedUser.getUsername());
// user.setEmail(updatedUser.getEmail());
// userRepository.save(user);

// String responseMessage;
// if (usernameChanged && emailChanged) {
// System.out.println("Enter if (usernameChanged && emailChanged)");
// responseMessage = "Username and email updated successfully.";
// } else if (usernameChanged) {
// System.out.println("Enter } else if (usernameChanged) {");
// responseMessage = "Username updated successfully.";
// } else if (emailChanged) {
// System.out.println("Enter } else if (emailChanged) {");
// responseMessage = "Email updated successfully.";
// } else {
// System.out.println("Enter } else {");
// responseMessage = "No changes detected.";
// }

// // return ResponseEntity.ok(responseMessage);
// // Return updated user and response message
// System.out.println("Above the return ResponseEntity.ok()");
// // return ResponseEntity.ok()
// // .body(new UpdateResponse(responseMessage, user));
// return ResponseEntity.ok()
// .body(new UpdateResponse(responseMessage, user.getUsername(),
// user.getEmail(), user.getId()));
// }

// // Placeholder for authentication check
// private boolean isAuthenticated() {
// // Implement your authentication logic here
// return true; // Placeholder
// }

// // Placeholder for permission check
// private boolean hasUpdatePermission(Long id) {
// // Implement your permission check logic here
// return true; // Placeholder
// }

// @DeleteMapping("/user/{id}")
// public ResponseEntity<?> deleteUser(@PathVariable Long id) {
// Optional<User> userOptional = userRepository.findById(id);
// if (userOptional.isPresent()) {
// userRepository.delete(userOptional.get());
// return ResponseEntity.ok("User deleted successfully");
// } else {
// return ResponseEntity.badRequest().body("User not found");
// }
// }

// }
// @PutMapping("/user/{usernameOrEmail}")
// public ResponseEntity<?> updateUser(@PathVariable String usernameOrEmail,
// @RequestBody User updatedUser) {
// Optional<User> userOptional =
// userRepository.findByUsernameOrEmail(usernameOrEmail);
// if (userOptional.isPresent()) {
// User user = userOptional.get();

// boolean usernameChanged =
// !user.getUsername().equals(updatedUser.getUsername());
// boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

// user.setUsername(updatedUser.getUsername());
// user.setEmail(updatedUser.getEmail());
// userRepository.save(user);

// String responseMessage = "User updated successfully.";
// if (usernameChanged && emailChanged) {
// responseMessage = "Username and email updated successfully.";
// } else if (usernameChanged) {
// responseMessage = "Username updated successfully.";
// } else if (emailChanged) {
// responseMessage = "Email updated successfully.";
// }

// return ResponseEntity.ok(responseMessage);
// } else {
// throw new UsernameNotFoundException("User not found with username or email: "
// + usernameOrEmail);
// }
// }

// @PutMapping("/user/{usernameOrEmail}")
// public ResponseEntity<?> updateUser(@PathVariable String usernameOrEmail,
// @RequestBody User updatedUser) {
// Optional<User> userOptional =
// userRepository.findByUsernameOrEmail(usernameOrEmail);
// if (userOptional.isPresent()) {
// User user = userOptional.get();

// boolean usernameChanged =
// !user.getUsername().equals(updatedUser.getUsername());
// boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

// user.setUsername(updatedUser.getUsername());
// user.setEmail(updatedUser.getEmail());
// userRepository.save(user);

// String responseMessage = "User updated successfully.";
// if (usernameChanged && emailChanged) {
// responseMessage = "Username and email updated successfully.";
// } else if (usernameChanged) {
// responseMessage = "Username updated successfully.";
// } else if (emailChanged) {
// responseMessage = "Email updated successfully.";
// }

// return ResponseEntity.ok(responseMessage);
// } else {
// throw new UsernameNotFoundException("User not found with username or email: "
// + usernameOrEmail);
// // return ResponseEntity.badRequest().body("User not found");
// // Use a more specific status code (optional)
// // return ResponseEntity.status(HttpStatus.NOT_FOUND)
// // .body("User not found with username or email: " + usernameOrEmail);
// }
// }
// @PutMapping("/user/{usernameOrEmail}")
// public ResponseEntity<?> updateUser(@PathVariable String usernameOrEmail,
// @RequestBody User updatedUser) {

// // Check authentication
// if (!isAuthenticated()) {
// throw new UnauthorizedException("You are not authorized to perform this
// operation.");
// }

// // Check update permission
// if (!hasUpdatePermission(usernameOrEmail)) {
// throw new ForbiddenException("You are not allowed to update this user.");
// }

// Optional<User> userOptional =
// userRepository.findByUsernameOrEmail(usernameOrEmail);
// if (userOptional.isEmpty()) {
// return ResponseEntity.badRequest().body("User not found");
// }

// User user = userOptional.get();

// boolean usernameChanged =
// !user.getUsername().equals(updatedUser.getUsername());
// boolean emailChanged = !user.getEmail().equals(updatedUser.getEmail());

// user.setUsername(updatedUser.getUsername());
// user.setEmail(updatedUser.getEmail());
// userRepository.save(user);

// String responseMessage;
// if (usernameChanged && emailChanged) {
// responseMessage = "Username and email updated successfully.";
// } else if (usernameChanged) {
// responseMessage = "Username updated successfully.";
// } else if (emailChanged) {
// responseMessage = "Email updated successfully.";
// } else {
// responseMessage = "No changes detected.";
// }

// return ResponseEntity.ok(responseMessage);
// }

// // Placeholder for authentication check
// private boolean isAuthenticated() {
// // Implement your authentication logic here
// return true; // Placeholder
// }

// // Placeholder for permission check
// private boolean hasUpdatePermission(String usernameOrEmail) {
// // Implement your permission check logic here
// return true; // Placeholder
// }

// @DeleteMapping("/user/{usernameOrEmail}")
// public ResponseEntity<?> deleteUser(@PathVariable String usernameOrEmail) {
// Optional<User> userOptional =
// userRepository.findByUsernameOrEmail(usernameOrEmail);
// if (userOptional.isPresent()) {
// userRepository.delete(userOptional.get());
// return ResponseEntity.ok("User deleted successfully");
// } else {
// return ResponseEntity.badRequest().body("User not found");
// }
// }

// ! End the code below is good

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.web.bind.annotation.*;

// import java.util.Optional;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private UserRepository userRepository;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest) {
// try {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// User user =
// userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
// .orElseThrow(() -> new BadCredentialsException(
// "User not found with username or email: " +
// authenticationRequest.getUsernameOrEmail()));

// String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail());

// // return ResponseEntity.ok(new AuthenticationResponse(jwt));
// return ResponseEntity.ok(new AuthenticationResponse(jwt, user.getUsername(),
// user.getEmail()));
// } catch (BadCredentialsException e) {
// return handleBadCredentialsException(authenticationRequest);
// }
// }

// private ResponseEntity<String>
// handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
// Optional<User> userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// if (authenticationRequest.getUsernameOrEmail().contains("@")) {
// return ResponseEntity.badRequest().body("You input email incorrect");
// } else {
// return ResponseEntity.badRequest().body("Input username incorrect");
// }
// }
// }

// ! End

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.web.bind.annotation.*;

// import java.util.Optional;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private UserRepository userRepository;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest) {
// try {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// // User user = userRepository
// // .findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail(),
// // authenticationRequest.getUsernameOrEmail())
// // .orElseThrow(() -> new BadCredentialsException(
// // "User not found with username or email: " +
// authenticationRequest.getUsernameOrEmail()));
// User user =
// userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
// .orElseThrow(() -> new BadCredentialsException("User not found with username
// or email: " + authenticationRequest.getUsernameOrEmail()));

// String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail());

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// } catch (BadCredentialsException e) {
// return handleBadCredentialsException(authenticationRequest);
// }
// }

// private ResponseEntity<String>
// handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
// Optional<User> userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// if (authenticationRequest.getUsernameOrEmail().contains("@")) {
// return ResponseEntity.badRequest().body("You input email incorrect");
// } else {
// return ResponseEntity.badRequest().body("Input username incorrect");
// }
// }
// }

// ! End

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;
// // import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.web.bind.annotation.*;

// import java.util.Optional;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private UserRepository userRepository;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest) {
// try {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// String jwt = jwtTokenUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// } catch (BadCredentialsException e) {
// return handleBadCredentialsException(authenticationRequest);
// }
// }

// private ResponseEntity<String>
// handleBadCredentialsException(AuthenticationRequest authenticationRequest) {
// Optional<User> userOptional =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// userOptional =
// userRepository.findByEmail(authenticationRequest.getUsernameOrEmail());
// if (userOptional.isPresent()) {
// return ResponseEntity.badRequest().body("Your input password is not
// correct");
// }

// if (authenticationRequest.getUsernameOrEmail().contains("@")) {
// return ResponseEntity.badRequest().body("You input email incorrect");
// } else {
// return ResponseEntity.badRequest().body("Input username incorrect");
// }
// }
// }

// ! End

// // AuthenticationController.java
// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private JwtUtil jwtUtil;

// @Autowired
// private UserDetailsService userDetailsService;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest)
// throws Exception {
// try {
// authenticationManager.authenticate(
// new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
// authenticationRequest.getPassword()));
// } catch (BadCredentialsException e) {
// throw new Exception("Incorrect username or password", e);
// }

// final UserDetails userDetails = userDetailsService
// .loadUserByUsername(authenticationRequest.getUsername());

// final String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// }
// }

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest) throws Exception {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword())
// );

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// }
// }

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @Autowired
// private UserRepository userRepository;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest)
// throws Exception {
// User userByUsername =
// userRepository.findByUsername(authenticationRequest.getUsernameOrEmail()).orElse(null);
// User userByEmail =
// userRepository.findByEmail(authenticationRequest.getUsernameOrEmail()).orElse(null);

// // Check if user is found by username
// if (userByUsername != null) {
// if (!passwordEncoder.matches(authenticationRequest.getPassword(),
// userByUsername.getPassword())) {
// return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Incorrect
// password");
// }
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(userByUsername.getUsername());
// String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// }

// // Check if user is found by email
// if (userByEmail != null) {
// if (!passwordEncoder.matches(authenticationRequest.getPassword(),
// userByEmail.getPassword())) {
// return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Incorrect
// password");
// }
// Authentication authentication = authenticationManager.authenticate(
// new UsernamePasswordAuthenticationToken(userByEmail.getEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(userByEmail.getUsername());
// String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// }

// // If user is not found by either username or email
// return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Username or email
// not found");
// }

// private boolean isEmail(String input) {
// return input.contains("@");
// }
// }

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest)
// throws Exception {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// }
// }

// package com.example.matching.controller;

// import com.example.matching.exception.IncorrectPasswordException;
// import com.example.matching.exception.UserNotFoundException;
// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.model.User;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest) {
// try {
// User user =
// userDetailsService.loadUserEntityByUsernameOrEmail(authenticationRequest.getUsernameOrEmail());

// if (!user.getPassword().equals(authenticationRequest.getPassword())) {
// throw new IncorrectPasswordException("Password incorrect");
// }

// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword())
// );

// SecurityContextHolder.getContext().setAuthentication(authentication);

// UserDetails userDetails =
// userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));

// } catch (UserNotFoundException e) {
// if (authenticationRequest.getUsernameOrEmail().contains("@")) {
// return ResponseEntity.status(401).body("Email incorrect");
// } else {
// return ResponseEntity.status(401).body("Username incorrect");
// }
// } catch (IncorrectPasswordException e) {
// return ResponseEntity.status(401).body("Password incorrect");
// } catch (BadCredentialsException e) {
// return ResponseEntity.status(401).body("Invalid credentials");
// }
// }
// }

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @PostMapping("/authenticate")
// public AuthenticationResponse createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest)
// throws Exception {
// Authentication authentication = authenticationManager.authenticate(
// new
// UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
// authenticationRequest.getPassword()));

// final UserDetails userDetails = userDetailsService
// .loadUserByUsername(authenticationRequest.getUsernameOrEmail());
// final String jwt = jwtUtil.generateToken(userDetails);

// return new AuthenticationResponse(jwt);
// }
// }

// // AuthenticationController.java
// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private JwtUtil jwtUtil;

// @Autowired
// private UserDetailsService userDetailsService;

// @PostMapping("/authenticate")
//
// esponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest
// authenticationRequest)
// throws Exception {
// {
// cationManager.authenticate(
// namePasswordAuthenticationToken(authenticationRequest.getUsername(),
// authenticationRequest.getPassword()));
// tch (BadCredentialsException e) {
// throw new Exception("Incorrect username or password", e);
// }

// erDetails userDetails = userDetailsService
// .loadUserByUsername(authenticationRequest.getUsername());

// final String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// // final String token = jwtUtil.generateToken(userDetails);

// // return ResponseEntity.ok(new AuthenticationResponse(token));
//

// package com.example.matching.controller;

// import com.example.matching.model.AuthenticationRequest;
// import com.example.matching.model.AuthenticationResponse;
// import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.web.bind.annotation.*;

// @RestController
// public class AuthenticationController {

// @Autowired
// private AuthenticationManager authenticationManager;

// @Autowired
// private JwtUtil jwtUtil;

// @Autowired
// private UserDetailsService userDetailsService;

// @PostMapping("/authenticate")
// public ResponseEntity<?> createAuthenticationToken(@RequestBody
// AuthenticationRequest authenticationRequest)
// throws Exception {
// try {
// authenticationManager.authenticate(
// new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(),
// authenticationRequest.getPassword()));
// } catch (BadCredentialsException e) {
// throw new Exception("Incorrect username or password", e);
// }

// final UserDetails userDetails = userDetailsService
// .loadUserByUsername(authenticationRequest.getUsername());

// final String jwt = jwtUtil.generateToken(userDetails);

// return ResponseEntity.ok(new AuthenticationResponse(jwt));
// }
// }
