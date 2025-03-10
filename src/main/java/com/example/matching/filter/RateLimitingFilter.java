package com.example.matching.filter;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private final Bucket bucket;

    public RateLimitingFilter() {
        // Define the bandwidth limit: 5 tokens per 2 minutes
        Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5, Duration.ofMinutes(2)));

        // Use the new way to create a bucket
        // this.bucket = Bucket4j.configurationBuilder()
        // .addLimit(limit)
        // .build();
        this.bucket = Bucket.builder()
                .addLimit(limit)
                .build();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Try to consume 1 token for each request
        if (bucket.tryConsume(1)) {
            // If a token is available, proceed with the request
            filterChain.doFilter(request, response);
        } else {
            // If no tokens are available, respond with 429 Too Many Requests
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.getWriter().write("Too many requests - try again later.");
        }
    }
}

// ! End
// package com.example.matching.filter;

// import io.github.bucket4j.Bandwidth;
// import io.github.bucket4j.Bucket;
// import io.github.bucket4j.Bucket4j;
// import io.github.bucket4j.Refill;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.http.HttpStatus;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;
// import java.time.Duration;

// @Component
// public class RateLimitingFilter extends OncePerRequestFilter {

// private final Bucket bucket;

// public RateLimitingFilter() {
// // Define the bandwidth limit: 10 tokens per minute
// // Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10,
// // Duration.ofMinutes(1)));
// Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5,
// Duration.ofMinutes(2)));
// // Create a token bucket with the defined limit
// this.bucket = Bucket4j.builder()
// .addLimit(limit)
// .build();
// }

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain filterChain)
// throws ServletException, IOException {

// // Try to consume 1 token for each request
// if (bucket.tryConsume(1)) {
// // If a token is available, proceed with the request
// filterChain.doFilter(request, response);
// } else {
// // If no tokens are available, respond with 429 Too Many Requests
// response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
// response.getWriter().write("Too many requests - try again later.");
// }
// }
// }

// ! End
// package com.example.matching.filter;

// import com.example.matching.model.User;
// import com.example.matching.repository.UserRepository;
// import com.example.matching.service.EmailService;
// import com.example.matching.service.EmailServiceForAdmin;

// import io.github.bucket4j.Bandwidth;
// import io.github.bucket4j.Bucket;
// import io.github.bucket4j.Bucket4j;
// import io.github.bucket4j.Refill;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.http.HttpStatus;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import java.io.IOException;
// import java.time.Duration;
// import java.time.LocalDateTime;
// import java.util.Optional;

// @Component
// public class RateLimitingFilter extends OncePerRequestFilter {

// @Autowired
// private UserRepository userRepository;

// @Autowired
// private EmailServiceForAdmin emailServiceForAdmin;

// private final Bucket bucket;

// public RateLimitingFilter() {
// Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5,
// Duration.ofMinutes(1)));
// this.bucket = Bucket4j.builder().addLimit(limit).build();
// }

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response,
// FilterChain filterChain) throws ServletException, IOException {
// String usernameOrEmail = request.getParameter("usernameOrEmail");
// Optional<User> userOptional =
// userRepository.findByUsernameOrEmail(usernameOrEmail);

// if (userOptional.isPresent()) {
// User user = userOptional.get();

// if (user.isLocked() && user.getLockUntil().isAfter(LocalDateTime.now())) {
// response.setStatus(HttpStatus.LOCKED.value());
// response.getWriter().write("Your account is locked. Contact admin to
// unlock.");
// return;
// }

// if (bucket.tryConsume(1)) {
// filterChain.doFilter(request, response);
// } else {
// handleTooManyRequests(user, response);
// }
// } else {
// filterChain.doFilter(request, response); // Let the request pass if user is
// not found
// }
// }

// private void handleTooManyRequests(User user, HttpServletResponse response)
// throws IOException {
// int currentViolationCount = user.getViolationCount();

// if (currentViolationCount == 0) {
// user.setViolationCount(1);
// user.setLockUntil(LocalDateTime.now().plusMinutes(7));
// response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
// response.getWriter().write("Too many requests - try again later. Account
// locked for 7 minutes.");
// } else if (currentViolationCount >= 1) {
// user.setViolationCount(2);
// user.setLocked(true);
// emailServiceForAdmin.sendAdminNotification(user); // Send email to admin
// response.setStatus(HttpStatus.LOCKED.value());
// response.getWriter().write("Your account is locked. Contact admin at
// admln19939@gmail.com to unlock.");
// }

// userRepository.save(user);
// }
// }

// ! End
// package com.example.matching.filter;

// import io.github.bucket4j.Bandwidth;
// import io.github.bucket4j.Bucket;
// import io.github.bucket4j.Refill;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import org.springframework.http.HttpStatus;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.example.matching.model.LoginRequest;
// import com.example.matching.model.UserDetailsForAdmin;
// import com.fasterxml.jackson.databind.ObjectMapper;

// import java.io.IOException;
// import java.time.Duration;
// import java.util.Map;
// import java.util.UUID;
// import java.util.concurrent.ConcurrentHashMap;

// @Component
// // public class RateLimitingFilter extends OncePerRequestFilter {
// public class RateLimitingFilter extends OncePerRequestFilter {

// private final Bucket bucket;

// private final Map<UserDetailsForAdmin, Integer> loginAttempts = new
// ConcurrentHashMap<>();
// private final Map<UserDetailsForAdmin, UUID> accountLockTime = new
// ConcurrentHashMap<>();

// private static final int MAX_ATTEMPTS = 5;
// // private static final long LOCK_TIME_MS = Duration.ofMinutes(5).toMillis();
// private static final long LOCK_TIME_MS = Duration.ofMinutes(2).toMillis();
// private static final String ADMIN_CONTACT = "admln19939@gmail.com";

// @SuppressWarnings("deprecation") // Suppress deprecation warning for
// Bucket4j.builder()
// public RateLimitingFilter() {
// // Bandwidth limit = Bandwidth.classic(10, Refill.intervally(10,
// // Duration.ofMinutes(1)));
// Bandwidth limit = Bandwidth.classic(5, Refill.intervally(5,
// Duration.ofMinutes(1)));
// // Using deprecated builder method with warning suppression
// this.bucket = io.github.bucket4j.Bucket4j.builder()
// .addLimit(limit)
// .build();
// }

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain filterChain)
// throws ServletException, IOException {

// // String usernameOrEmail = request.getParameter("usernameOrEmail");

// // // Skip actual authentication; just check the login attempts and rate
// limit
// // UserDetailsForAdmin user = new UserDetailsForAdmin(usernameOrEmail,
// // usernameOrEmail); // Simplified for demonstration

// // String usernameOrEmail = request.getParameter("usernameOrEmail");

// // // Ensure usernameOrEmail is not null
// // if (usernameOrEmail == null || usernameOrEmail.isEmpty()) {
// // response.setStatus(HttpStatus.BAD_REQUEST.value());
// // response.getWriter().write("Username or email cannot be null.");
// // return;
// // }

// // Read JSON body
// ObjectMapper objectMapper = new ObjectMapper();
// LoginRequest loginRequest = objectMapper.readValue(request.getInputStream(),
// LoginRequest.class);

// String usernameOrEmail = loginRequest.getUsernameOrEmail();

// // Ensure usernameOrEmail is not null
// if (usernameOrEmail == null || usernameOrEmail.isEmpty()) {
// response.setStatus(HttpStatus.BAD_REQUEST.value());
// response.getWriter().write("Username or email cannot be null.");
// return;
// }

// UserDetailsForAdmin user = new UserDetailsForAdmin(usernameOrEmail,
// usernameOrEmail);

// if (isAccountLocked(user)) {
// response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
// response.getWriter().write("Your account is locked. Please try again after 5
// minutes or contact "
// + ADMIN_CONTACT + " to unlock your account.");
// return;
// }

// if (bucket.tryConsume(1)) {
// boolean loginSuccess = authenticate(request);

// if (loginSuccess) {
// // Reset login attempts on successful login
// loginAttempts.put(user, 0);
// filterChain.doFilter(request, response);
// } else {
// int attempts = loginAttempts.getOrDefault(user, 0) + 1;
// loginAttempts.put(user, attempts);

// if (attempts >= MAX_ATTEMPTS) {
// accountLockTime.put(user, UUID.randomUUID()); // Lock the account
// response.setStatus(HttpStatus.LOCKED.value());
// response.getWriter().write(
// "Your account is locked due to too many failed attempts. Please try again
// after 5 minutes or contact "
// + ADMIN_CONTACT + " to unlock your account.");
// } else {
// // Add the "remaining attempts" message
// response.setStatus(HttpStatus.UNAUTHORIZED.value());
// response.getWriter()
// .write("Invalid credentials. You have " + (MAX_ATTEMPTS - attempts) + "
// attempts left.");
// }
// }
// } else {
// response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
// response.getWriter().write("Too many requests - try again later.");
// }
// }

// private boolean authenticate(HttpServletRequest request) {
// // Placeholder for actual authentication logic
// String username = request.getParameter("username");
// String password = request.getParameter("password");
// return "admin".equals(username) && "password123".equals(password); //
// Simplified
// }

// // Check if the account is locked
// // private boolean isAccountLocked(UserDetailsForAdmin user) {
// // if (!accountLockTime.containsKey(user)) {
// // return false;
// // }

// // long currentTime = System.currentTimeMillis();
// // UUID lockId = accountLockTime.get(user);
// // if (currentTime - lockId.timestamp() > LOCK_TIME_MS) {
// // accountLockTime.remove(user);
// // loginAttempts.put(user, 0); // Reset attempts after unlock
// // return false;
// // }

// // return true;
// // }

// private boolean isAccountLocked(UserDetailsForAdmin user) {
// if (!accountLockTime.containsKey(user)) {
// return false;
// }

// long currentTime = System.currentTimeMillis();
// UUID lockId = accountLockTime.get(user);
// if (currentTime - lockId.timestamp() > LOCK_TIME_MS) {
// accountLockTime.remove(user);
// loginAttempts.put(user, 0); // Reset attempts after unlock
// return false;
// }

// return true;
// }

// // Method to track failed login attempts and handle account locking
// public void trackFailedLoginAttempt(UserDetailsForAdmin user) {
// int attempts = loginAttempts.getOrDefault(user, 0) + 1;
// loginAttempts.put(user, attempts);

// if (attempts >= MAX_ATTEMPTS) {
// accountLockTime.put(user, UUID.randomUUID()); // Using UUID to represent lock
// event
// }
// }

// // Method to reset login attempts and unlock accounts (useful for admin
// unlock
// // functionality)
// public void resetLoginAttempts(UserDetailsForAdmin user) {
// loginAttempts.remove(user);
// accountLockTime.remove(user);
// }

// // Getter methods to access from AdminController
// public Map<UserDetailsForAdmin, Integer> getLoginAttempts() {
// return loginAttempts;
// }

// public Map<UserDetailsForAdmin, UUID> getAccountLockTime() {
// return accountLockTime;
// }
// }
