package com.example.matching.config;

import com.example.matching.repository.BlacklistedTokenRepository;
import com.example.matching.service.CustomUserDetailsService;
import com.example.matching.util.JwtTokenUtil;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.UUID;
import java.util.logging.Logger;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String jwtToken = null;

        // Check Authorization header first
        final String requestTokenHeader = request.getHeader("Authorization");
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
        }
        // If token not found in Authorization header, check cookies
        else {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if ("jwtToken".equals(cookie.getName())) {
                        jwtToken = cookie.getValue();
                        break;
                    }
                }
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{ \"message\": \"Token has been revoke\"}");
                return;
            }
        }

        UUID userId = null;
        if (jwtToken != null) {
            try {
                // Extract userId from the JWT token
                userId = jwtTokenUtil.getUserIdFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                logger.error("Unable to get JWT Token");
                // logger.warning("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                logger.error("JWT Token has expired");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter()
                        .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" +
                                e.getMessage() + "\" }");
                return;
            }
        } else {
            logger.error("JWT Token not found or does not begin with Bearer String");
        }

        // Validate the token if the userId is not null and no existing authentication
        // in context
        if (userId != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            try {
                // Load the user details using userId
                UserDetails userDetails = this.userDetailsService.loadUserById(userId);

                // Hash the token for blacklist check
                String hashedToken = HashUtil.hashToken(jwtToken);

                // Check if the token has been blacklisted
                if (blacklistedTokenRepository.findByToken(hashedToken).isPresent()) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{ \"message\": \"Token has been blacklisted\"}");
                    return;
                }

                // If the token is valid, set authentication in the security context
                if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    // Set the authentication in the context so it is recognized by Spring Security
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            } catch (UsernameNotFoundException e) {
                logger.error("User not found: " + e.getMessage());
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.setContentType("application/json");
                response.getWriter()
                        .write("{ \"error\": \"Forbidden\", \"message\": \"User not found with userId JwtRequestFilter: "
                                + userId + "\" }");
                return;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        // Proceed with the filter chain
        chain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        // Skip filtering for specific paths like "/authenticate", "/register", etc.
        return path.startsWith("/authenticate") || path.startsWith("/register") || path.startsWith("/password-reset");
    }

}

// ! No check for the JWT token in both the Authorization header and cookies
// package com.example.matching.config;

// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import java.io.IOException;
// import java.util.logging.Logger;
// import java.util.*;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// UUID userId = null;
// String jwtToken = null;
// // JWT Token is in the form "Bearer token". Remove Bearer word and get only
// the Token
// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// userId = jwtTokenUtil.getUserIdFromToken(jwtToken); // Fixed line
// // userId = Long.valueOf(jwtTokenUtil.getUserIdFromToken(jwtToken));
// } catch (IllegalArgumentException e) {
// System.out.println("Unable to get JWT Token");
// } catch (ExpiredJwtException e) {
// System.out.println("JWT Token has expired");
// // Custom error handling
// logger.error("Token parsing failed: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// e.getMessage() + "\" }");
// return;
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// // Once we get the token validate it.
// if (userId != null && SecurityContextHolder.getContext().getAuthentication()
// == null) {

// try {
// UserDetails userDetails = this.userDetailsService.loadUserById(userId);

// String incomingJwtToken = jwtToken;// Extract the JWT token from the request
// header;
// String hashedToken = HashUtil.hashToken(incomingJwtToken);
// // boolean isBlacklisted =
// blacklistedTokenRepository.findByToken(hashedToken);
// // Check if token is blacklisted
// if (blacklistedTokenRepository.findByToken(hashedToken).isPresent()) {
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.getWriter().write("{ \"message\": \"Token has been blacklisted\"}");
// return;
// }
// // if (blacklistedTokenRepository.findByToken(jwtToken).isPresent()) {
// // response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// // response.getWriter().write("{ \"message\": \"Token has been
// blacklisted\"}");
// // return;
// // }

// // if token is valid configure Spring Security to manually set authentication
// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// System.out.println("#### 2.5");
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// // After setting the Authentication in the context, we specify
// // that the current user is authenticated. So it passes the Spring Security
// // Configurations successfully.
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// } catch (UsernameNotFoundException e) {
// logger.error("User not found: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Forbidden\", \"message\": \"User not found with userId
// JwtRequestFilter: "
// + userId + "\" }");
// return;
// } catch (IOException e) {
// e.printStackTrace();
// }
// }
// chain.doFilter(request, response);
// }
// }

// ! Still Long id
// package com.example.matching.config;

// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import java.io.IOException;
// import java.util.logging.Logger;
// import java.util.*;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// UUID userId = null;
// String jwtToken = null;
// // JWT Token is in the form "Bearer token". Remove Bearer word and get only
// the Token
// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// userId = jwtTokenUtil.getUserIdFromToken(jwtToken); // Fixed line
// // userId = Long.valueOf(jwtTokenUtil.getUserIdFromToken(jwtToken));
// } catch (IllegalArgumentException e) {
// System.out.println("Unable to get JWT Token");
// } catch (ExpiredJwtException e) {
// System.out.println("JWT Token has expired");
// // Custom error handling
// logger.error("Token parsing failed: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// e.getMessage() + "\" }");
// return;
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// // Once we get the token validate it.
// if (userId != null && SecurityContextHolder.getContext().getAuthentication()
// == null) {

// try {
// UserDetails userDetails = this.userDetailsService.loadUserById(userId);

// // Check if token is blacklisted
// if (blacklistedTokenRepository.findByToken(jwtToken).isPresent()) {
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.getWriter().write("{ \"message\": \"Token has been blacklisted\"}");
// return;
// }

// // if token is valid configure Spring Security to manually set authentication
// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// System.out.println("#### 2.5");
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// // After setting the Authentication in the context, we specify
// // that the current user is authenticated. So it passes the Spring Security
// // Configurations successfully.
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// } catch (UsernameNotFoundException e) {
// logger.error("User not found: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Forbidden\", \"message\": \"User not found with userId
// JwtRequestFilter: "
// + userId + "\" }");
// return;
// } catch (IOException e) {
// e.printStackTrace();
// }
// }
// chain.doFilter(request, response);
// }
// }

// ! End

// package com.example.matching.config;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;

// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// String usernameOrEmail = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// usernameOrEmail = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (IllegalArgumentException e) {
// logger.error("Unable to get JWT Token");
// } catch (ExpiredJwtException e) {
// logger.error("JWT Token has expired");
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// e.getMessage() + "\" }");
// return;
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// if (usernameOrEmail == null) {
// // Extract the username or email from the request URL
// String requestURI = request.getRequestURI();
// usernameOrEmail = requestURI.substring(requestURI.lastIndexOf('/') + 1);
// }

// if (usernameOrEmail != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// try {
// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(usernameOrEmail);

// if (blacklistedTokenRepository.findByToken(jwtToken).isPresent()) {
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.getWriter().write("{ \"message\": \"Token has been blacklisted\"
// }");
// return;
// }

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// } catch (UsernameNotFoundException e) {
// logger.error("User not found: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Forbidden\", \"message\": \"User not found with
// username or email JwtRequestFilter: "
// + usernameOrEmail + "\" }");
// return;
// }
// }

// chain.doFilter(request, response);
// }
// }

// ! below code is good and it check username

// JwtRequestFilter.java
// package com.example.matching.config;

// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;
// // JWT Token is in the form "Bearer token". Remove Bearer word and get only
// the
// // Token
// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (IllegalArgumentException e) {
// System.out.println("Unable to get JWT Token");
// } catch (ExpiredJwtException e) {
// System.out.println("JWT Token has expired");
// // * this custom error */
// logger.error("Token parsing failed: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// e.getMessage() + "\" }");
// return;
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// // Once we get the token validate it.
// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {

// try {
// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(username);

// // Check if token is blacklisted
// if (blacklistedTokenRepository.findByToken(jwtToken).isPresent()) {
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.getWriter().write("{ \"message\": \"Token has been blacklisted\"}");
// return;
// }

// // if token is valid configure Spring Security to manually set authentication
// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {

// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// // After setting the Authentication in the context, we
// specifyewEmail@example.com
// // that the current user is authenticated. So it passes the Spring Security
// // Configurations successfully.
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// } catch (UsernameNotFoundException e) {
// // TODO Auto-generated catch block
// // e.printStackTrace();
// logger.error("User not found: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Forbidden\", \"message\": \"User not found with
// username or email JwtRequestFilter: "
// + username + "\" }");
// // response.getWriter()
// // .write("{ \"error\": \"Forbidden\", \"message\": \"User not found with
// username or email JwtRequestFilter: "
// // + usernameOrEmail + "\" }");
// return;
// } catch (IOException e) {
// // TODO Auto-generated catch block
// e.printStackTrace();
// }
// }
// chain.doFilter(request, response);
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private CustomUserDetailsService customUserDetailsService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (Exception e) {
// logger.error("Token parsing failed: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// e.getMessage() + "\" }");
// return;
// }
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// this.customUserDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }

// chain.doFilter(request, response);
// }
// }

// ? End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.service.TokenBlacklistService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import io.jsonwebtoken.SignatureException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private TokenBlacklistService tokenBlacklistService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {

// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// if (tokenBlacklistService.isTokenBlacklisted(jwtToken)) {
// throw new SignatureException("Token has been blacklisted");
// }
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (IllegalArgumentException e) {
// throw new RuntimeException("Unable to get JWT Token", e);
// } catch (ExpiredJwtException e) {
// throw new RuntimeException("JWT Token has expired", e);
// } catch (SignatureException e) {
// throw new RuntimeException("JWT Token is invalid", e);
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.service.TokenBlacklistService;
// import com.example.matching.util.JwtTokenUtil;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;
// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService customUserDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private TokenBlacklistService tokenBlacklistService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {

// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// // JWT Token is in the form "Bearer token"
// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);

// try {
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (IllegalArgumentException e) {
// System.out.println("Unable to get JWT Token");
// } catch (ExpiredJwtException e) {
// System.out.println("JWT Token has expired");
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// // Validate the token and check if it is blacklisted
// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// customUserDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)
// && !tokenBlacklistService.isTokenBlacklisted(jwtToken)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private CustomUserDetailsService customUserDetailsService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain) throws ServletException,
// IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (Exception e) {
// logger.error("Token parsing failed: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter().write("{ \"error\": \"Token expired or invalid\",
// \"message\": \"" + e.getMessage() + "\" }");
// return;
// }
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// this.customUserDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
// new UsernamePasswordAuthenticationToken(userDetails, null,
// userDetails.getAuthorities());
// usernamePasswordAuthenticationToken.setDetails(new
// WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }

// chain.doFilter(request, response);
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.service.TokenBlacklistService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import io.jsonwebtoken.SignatureException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private TokenBlacklistService tokenBlacklistService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {

// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// if (tokenBlacklistService.isTokenBlacklisted(jwtToken)) {
// throw new SignatureException("Token has been blacklisted");
// }
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (IllegalArgumentException e) {
// response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unable to get JWT
// Token");
// return;
// } catch (ExpiredJwtException e) {
// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT Token has
// expired");
// return;
// } catch (SignatureException e) {
// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "JWT Token is
// invalid");
// return;
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }

// todo End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.service.TokenBlacklistService;
// import com.example.matching.util.JwtTokenUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import io.jsonwebtoken.SignatureException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private TokenBlacklistService tokenBlacklistService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {

// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// if (tokenBlacklistService.isTokenBlacklisted(jwtToken)) {
// throw new SignatureException("Token has been blacklisted");
// }
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (IllegalArgumentException e) {
// throw new RuntimeException("Unable to get JWT Token", e);
// } catch (ExpiredJwtException e) {
// throw new RuntimeException("JWT Token has expired", e);
// } catch (SignatureException e) {
// throw new RuntimeException("JWT Token is invalid", e);
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }

// ? End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.service.TokenBlacklistService;
// import com.example.matching.util.JwtTokenUtil;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;
// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService customUserDetailsService;

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private TokenBlacklistService tokenBlacklistService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {

// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// // JWT Token is in the form "Bearer token"
// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);

// try {
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (IllegalArgumentException e) {
// System.out.println("Unable to get JWT Token");
// } catch (ExpiredJwtException e) {
// System.out.println("JWT Token has expired");
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// // Validate the token and check if it is blacklisted
// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// customUserDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)
// && !tokenBlacklistService.isTokenBlacklisted(jwtToken)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }

// !End

// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtTokenUtil;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private JwtTokenUtil jwtTokenUtil;

// @Autowired
// private CustomUserDetailsService customUserDetailsService;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// username = jwtTokenUtil.getUsernameFromToken(jwtToken);
// } catch (Exception e) {
// logger.error("Token parsing failed: " + e.getMessage());
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter()
// .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// e.getMessage() + "\" }");
// return;
// }
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// this.customUserDetailsService.loadUserByUsername(username);

// if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }

// chain.doFilter(request, response);
// }
// }

// // JwtRequestFilter.java
// package com.example.matching.config;

// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.example.matching.util.JwtUtil;

// import io.jsonwebtoken.ExpiredJwtException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.*;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private UserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {
// final String requestTokenHeader = request.getHeader("Authorization");

// String username = null;
// String jwtToken = null;

// if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
// jwtToken = requestTokenHeader.substring(7);
// try {
// username = jwtUtil.extractUsername(jwtToken);
// } catch (ExpiredJwtException e) {
// // Token is expired
// request.setAttribute("expired", e.getMessage());
// // Proceed without setting the security context
// } catch (Exception e) {
// logger.error("Error occurred while extracting username from token", e);
// }
// } else {
// logger.warn("JWT Token does not begin with Bearer String");
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {
// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(username);

// if (jwtUtil.validateToken(jwtToken, userDetails)) {
// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtUtil;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.*;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;
// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {

// final String authorizationHeader = request.getHeader("Authorization");

// String username = null;
// String jwt = null;

// if (authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
// {
// jwt = authorizationHeader.substring(7);
// username = jwtUtil.extractUsername(jwt);
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {

// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(username);

// if (jwtUtil.validateToken(jwt, userDetails)) {

// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }

// package com.example.matching.config;

// // package com.example.matching.config;

// // import com.example.matching.service.CustomUserDetailsService;
// // import com.example.matching.util.JwtUtil;
// import org.springframework.beans.factory.annotation.Autowired;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import
// org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtUtil;

// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtUtil jwtUtil;

// @Override
// protected void doFilterInternal(HttpServletRequest request,
// HttpServletResponse response, FilterChain chain)
// throws ServletException, IOException {

// final String authorizationHeader = request.getHeader("Authorization");

// String username = null;
// String jwt = null;

// if (authorizationHeader != null && authorizationHeader.startsWith("Bearer "))
// {
// jwt = authorizationHeader.substring(7);
// username = jwtUtil.extractUsername(jwt);
// }

// if (username != null &&
// SecurityContextHolder.getContext().getAuthentication() == null) {

// UserDetails userDetails =
// this.userDetailsService.loadUserByUsername(username);

// if (jwtUtil.validateToken(jwt, userDetails)) {

// UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new
// UsernamePasswordAuthenticationToken(
// userDetails, null, userDetails.getAuthorities());
// usernamePasswordAuthenticationToken
// .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
// SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
// }
// }
// chain.doFilter(request, response);
// }
// }
