// JwtRequestFilter.java
package com.example.matching.config;

import com.example.matching.repository.BlacklistedTokenRepository;
import com.example.matching.service.CustomUserDetailsService;
import com.example.matching.util.JwtTokenUtil;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

// import javax.servlet.FilterChain;
// import javax.servlet.ServletException;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtTokenUtil jwtTokenUtil;

    @Autowired
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        final String requestTokenHeader = request.getHeader("Authorization");

        String username = null;
        String jwtToken = null;
        // JWT Token is in the form "Bearer token". Remove Bearer word and get only the
        // Token
        if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
            jwtToken = requestTokenHeader.substring(7);
            try {
                username = jwtTokenUtil.getUsernameFromToken(jwtToken);
            } catch (IllegalArgumentException e) {
                System.out.println("Unable to get JWT Token");
            } catch (ExpiredJwtException e) {
                System.out.println("JWT Token has expired");
                //* this custom error */
                logger.error("Token parsing failed: " + e.getMessage());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter()
                        .write("{ \"error\": \"Token expired or invalid\", \"message\": \"" + e.getMessage() + "\" }");
                return;
            }
        } else {
            logger.warn("JWT Token does not begin with Bearer String");
        }

        // Once we get the token validate it.
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Check if token is blacklisted
            if (blacklistedTokenRepository.findByToken(jwtToken).isPresent()) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{ \"message\": \"Token has been blacklisted\" }");
                return;
            }

            // if token is valid configure Spring Security to manually set authentication
            if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {

                UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities());
                usernamePasswordAuthenticationToken
                        .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                // After setting the Authentication in the context, we specify
                // that the current user is authenticated. So it passes the Spring Security
                // Configurations successfully.
                SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
            }
        }
        chain.doFilter(request, response);
    }
}

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
