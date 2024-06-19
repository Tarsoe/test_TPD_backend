// package com.example.matching.util;

// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.service.TokenBlacklistService;
// import io.jsonwebtoken.ExpiredJwtException;
// import io.jsonwebtoken.SignatureException;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
// import org.springframework.stereotype.Component;
// import org.springframework.web.filter.OncePerRequestFilter;

// // import javax.servlet.FilterChain;
// // import javax.servlet.ServletException;
// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class JwtRequestFilter extends OncePerRequestFilter {

//     @Autowired
//     private CustomUserDetailsService userDetailsService;

//     @Autowired
//     private JwtTokenUtil jwtTokenUtil;

//     @Autowired
//     private TokenBlacklistService tokenBlacklistService;

//     @Override
//     protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
//             throws ServletException, IOException {

//         final String requestTokenHeader = request.getHeader("Authorization");

//         String username = null;
//         String jwtToken = null;

//         if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
//             jwtToken = requestTokenHeader.substring(7);
//             try {
//                 if (tokenBlacklistService.isTokenBlacklisted(jwtToken)) {
//                     throw new RuntimeException("Token has been blacklisted");
//                 }
//                 username = jwtTokenUtil.getUsernameFromToken(jwtToken);
//             } catch (IllegalArgumentException e) {
//                 throw new RuntimeException("Unable to get JWT Token", e);
//             } catch (ExpiredJwtException e) {
//                 throw new RuntimeException("JWT Token has expired", e);
//             } catch (SignatureException e) {
//                 throw new RuntimeException("JWT Token is invalid", e);
//             }
//         } else {
//             logger.warn("JWT Token does not begin with Bearer String");
//         }

//         if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//             UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

//             if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
//                 UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
//                         userDetails, null, userDetails.getAuthorities());
//                 usernamePasswordAuthenticationToken
//                         .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                 SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
//             }
//         }
//         chain.doFilter(request, response);
//     }
// }
