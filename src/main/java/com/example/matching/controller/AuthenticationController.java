package com.example.matching.controller;

import com.example.matching.model.AuthenticationRequest;
import com.example.matching.model.AuthenticationResponse;
import com.example.matching.model.User;
import com.example.matching.repository.UserRepository;
import com.example.matching.service.CustomUserDetailsService;
import com.example.matching.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

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
    public ResponseEntity<?> createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authenticationRequest.getUsernameOrEmail(),
                            authenticationRequest.getPassword()));

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsernameOrEmail());
            User user = userRepository.findByUsernameOrEmail(authenticationRequest.getUsernameOrEmail())
                    .orElseThrow(() -> new BadCredentialsException(
                            "User not found with username or email: " + authenticationRequest.getUsernameOrEmail()));

            String jwt = jwtTokenUtil.generateToken(userDetails, user.getEmail());

            // return ResponseEntity.ok(new AuthenticationResponse(jwt));
            return ResponseEntity.ok(new AuthenticationResponse(jwt, user.getUsername(), user.getEmail()));
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

        if (authenticationRequest.getUsernameOrEmail().contains("@")) {
            return ResponseEntity.badRequest().body("You input email incorrect");
        } else {
            return ResponseEntity.badRequest().body("Input username incorrect");
        }
    }
}

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
