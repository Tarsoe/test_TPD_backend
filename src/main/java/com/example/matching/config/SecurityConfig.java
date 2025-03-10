package com.example.matching.config;

import com.example.matching.exception.CustomAuthenticationEntryPoint;
import com.example.matching.filter.RateLimitingFilter;
import com.example.matching.model.BlacklistedToken;
import com.example.matching.repository.BlacklistedTokenRepository;
import com.example.matching.exception.CustomAccessDeniedHandler;
import com.example.matching.service.CustomUserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.http.Cookie;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

    @Autowired
    private CustomAccessDeniedHandler customAccessDeniedHandler;

    @Autowired
    private BlacklistedTokenRepository blacklistedTokenRepository;

    @Autowired
    private RateLimitingFilter rateLimitingFilter; // Add the rate limiting filter

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/register", "/authenticate", "/logout", "/password-reset/**")
                        .permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // .addFilterBefore(jwtRequestFilter,
                // UsernamePasswordAuthenticationFilter.class)
                // .addFilterBefore(rateLimitingFilter, OncePerRequestFilter.class)
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class) // Add before auth filter
                .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class) // Add before auth
                                                                                                 // filter
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler()));

        return http.build();
    }

    @Bean
    public HttpFirewall strictHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedSlash(true);
        firewall.setAllowSemicolon(true);
        firewall.setAllowUrlEncodedPercent(true);
        firewall.setAllowBackSlash(true);
        firewall.setAllowUrlEncodedPeriod(true);
        return firewall;
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.httpFirewall(strictHttpFirewall());
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return (request, response, authentication) -> {
            // Invalidate token from Authorization header (Bearer token)
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwtToken = authHeader.substring(7); // Extract JWT token
                String hashedToken = HashUtil.hashToken(jwtToken); // Hash the JWT token
                blacklistedTokenRepository.save(new BlacklistedToken(hashedToken)); // Save hashed token to the database
            }

            // Invalidate token stored in the cookie
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    // if ("token".equals(cookie.getName())) {
                    if ("jwtToken".equals(cookie.getName())) {
                        cookie.setValue(null);
                        cookie.setPath("/");
                        cookie.setMaxAge(0); // Expire the cookie
                        response.addCookie(cookie);
                    }
                }
            }

            // Respond with successful logout message
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().write("{ \"message\": \"You have been logged out successfully.\" }");
        };
    }
}

//! Below code is check cookie when user login
// package com.example.matching.config;

// import com.example.matching.exception.CustomAuthenticationEntryPoint;
// import com.example.matching.filter.RateLimitingFilter;
// import com.example.matching.model.BlacklistedToken;
// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.exception.CustomAccessDeniedHandler;
// import com.example.matching.service.CustomUserDetailsService;
// import jakarta.servlet.http.HttpServletResponse;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
// import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
// import org.springframework.security.web.firewall.HttpFirewall;
// import org.springframework.security.web.firewall.StrictHttpFirewall;
// import org.springframework.web.filter.OncePerRequestFilter;

// import jakarta.servlet.http.Cookie;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

//     @Autowired
//     private CustomUserDetailsService userDetailsService;

//     @Autowired
//     private JwtRequestFilter jwtRequestFilter;

//     @Autowired
//     private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;

//     @Autowired
//     private CustomAccessDeniedHandler customAccessDeniedHandler;

//     @Autowired
//     private BlacklistedTokenRepository blacklistedTokenRepository;

//     @Autowired
//     private RateLimitingFilter rateLimitingFilter; // Add the rate limiting filter

//     @Bean
//     public PasswordEncoder passwordEncoder() {
//         return new BCryptPasswordEncoder();
//     }

//     @Bean
//     public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
//             throws Exception {
//         return authenticationConfiguration.getAuthenticationManager();
//     }

//     // @Bean
//     // public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
//     // Exception {
//     // http.csrf().disable()
//     // .authorizeHttpRequests(authz -> authz
//     // .requestMatchers("/register", "/authenticate", "/logout",
//     // "/password-reset/request",
//     // "/password-reset/validate", "/password-reset/reset")
//     // .permitAll()
//     // .anyRequest().authenticated())
//     // .sessionManagement(session ->
//     // session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//     // .addFilterBefore(jwtRequestFilter,
//     // UsernamePasswordAuthenticationFilter.class)
//     // .addFilterBefore(rateLimitingFilter, OncePerRequestFilter.class) // Add rate
//     // limiting filter before the others
//     // .exceptionHandling()
//     // .authenticationEntryPoint(customAuthenticationEntryPoint)
//     // .accessDeniedHandler(customAccessDeniedHandler)
//     // .and()
//     // .logout(logout -> logout
//     // .logoutUrl("/logout")
//     // .logoutSuccessHandler(logoutSuccessHandler()));

//     // // Apply the custom HttpFirewall
//     // http.apply(new CustomHttpFirewallConfigurer());

//     // return http.build();
//     // }
//     @Bean
//     public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//         http
//                 .csrf(csrf -> csrf.disable())
//                 .authorizeHttpRequests(authz -> authz
//                         .requestMatchers("/register", "/authenticate", "/logout", "/password-reset/**")
//                         .permitAll()
//                         .anyRequest().authenticated())
//                 .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                 // .addFilterBefore(jwtRequestFilter,
//                 // UsernamePasswordAuthenticationFilter.class)
//                 // .addFilterBefore(rateLimitingFilter, OncePerRequestFilter.class)
//                 .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class) // Add before auth filter
//                 .addFilterBefore(rateLimitingFilter, UsernamePasswordAuthenticationFilter.class) // Add before auth
//                                                                                                  // filter
//                 .exceptionHandling(exceptionHandling -> exceptionHandling
//                         .authenticationEntryPoint(customAuthenticationEntryPoint)
//                         .accessDeniedHandler(customAccessDeniedHandler))
//                 .logout(logout -> logout
//                         .logoutUrl("/logout")
//                         .logoutSuccessHandler(logoutSuccessHandler()));

//         return http.build();
//     }

//     @Bean
//     public HttpFirewall strictHttpFirewall() {
//         StrictHttpFirewall firewall = new StrictHttpFirewall();
//         firewall.setAllowUrlEncodedSlash(true);
//         firewall.setAllowSemicolon(true);
//         firewall.setAllowUrlEncodedPercent(true);
//         firewall.setAllowBackSlash(true);
//         firewall.setAllowUrlEncodedPeriod(true);
//         return firewall;
//     }

//     @Bean
//     public WebSecurityCustomizer webSecurityCustomizer() {
//         return (web) -> web.httpFirewall(strictHttpFirewall());
//     }

//     // @Bean
//     // public LogoutSuccessHandler logoutSuccessHandler() {
//     // return (request, response, authentication) -> {
//     // String authHeader = request.getHeader("Authorization");
//     // if (authHeader != null && authHeader.startsWith("Bearer ")) {
//     // String jwtToken = authHeader.substring(7);
//     // blacklistedTokenRepository.save(new BlacklistedToken(jwtToken));
//     // }
//     // response.setStatus(HttpServletResponse.SC_OK);
//     // response.setContentType("application/json");
//     // response.getWriter().write("{ \"message\": \"You have been logged out
//     // successfully.\" }");
//     // };
//     // }

//     // ! Good
//     // @Bean
//     // public LogoutSuccessHandler logoutSuccessHandler() {
//     // return (request, response, authentication) -> {
//     // String authHeader = request.getHeader("Authorization");
//     // if (authHeader != null && authHeader.startsWith("Bearer ")) {
//     // String jwtToken = authHeader.substring(7); // Extract JWT token
//     // String hashedToken = HashUtil.hashToken(jwtToken); // Hash the JWT token
//     // blacklistedTokenRepository.save(new BlacklistedToken(hashedToken)); // Save
//     // hashed token to the database
//     // }
//     // response.setStatus(HttpServletResponse.SC_OK);
//     // response.setContentType("application/json");
//     // response.getWriter().write("{ \"message\": \"You have been logged out
//     // successfully.\" }");
//     // };
//     // }

//     @Bean
//     public LogoutSuccessHandler logoutSuccessHandler() {
//         return (request, response, authentication) -> {
//             // Invalidate token from Authorization header (Bearer token)
//             String authHeader = request.getHeader("Authorization");
//             if (authHeader != null && authHeader.startsWith("Bearer ")) {
//                 String jwtToken = authHeader.substring(7); // Extract JWT token
//                 String hashedToken = HashUtil.hashToken(jwtToken); // Hash the JWT token
//                 blacklistedTokenRepository.save(new BlacklistedToken(hashedToken)); // Save hashed token to the database
//             }

//             // Invalidate token stored in the cookie
//             Cookie[] cookies = request.getCookies();
//             if (cookies != null) {
//                 for (Cookie cookie : cookies) {
//                     // if ("token".equals(cookie.getName())) {
//                     if ("jwtToken".equals(cookie.getName())) {
//                         cookie.setValue(null);
//                         cookie.setPath("/");
//                         cookie.setMaxAge(0); // Expire the cookie
//                         response.addCookie(cookie);
//                     }
//                 }
//             }

//             // Respond with successful logout message
//             response.setStatus(HttpServletResponse.SC_OK);
//             response.setContentType("application/json");
//             response.getWriter().write("{ \"message\": \"You have been logged out successfully.\" }");
//         };
//     }

//     // @Bean
//     // public HttpFirewall strictHttpFirewall() {
//     // StrictHttpFirewall firewall = new StrictHttpFirewall();
//     // firewall.setAllowUrlEncodedSlash(true);
//     // firewall.setAllowSemicolon(true);
//     // firewall.setAllowUrlEncodedPercent(true);
//     // firewall.setAllowBackSlash(true);
//     // firewall.setAllowUrlEncodedPeriod(true);
//     // return firewall;
//     // }

//     // public class CustomHttpFirewallConfigurer
//     // extends AbstractHttpConfigurer<CustomHttpFirewallConfigurer, HttpSecurity> {
//     // @Override
//     // public void init(HttpSecurity http) throws Exception {
//     // http.setSharedObject(HttpFirewall.class, strictHttpFirewall());
//     // }
//     // }
// }

// ! Code below is code

// package com.example.matching.config;

// import com.example.matching.model.BlacklistedToken;
// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;
// import jakarta.servlet.http.HttpServletResponse;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import
// org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
// import org.springframework.security.web.firewall.HttpFirewall;
// import org.springframework.security.web.firewall.StrictHttpFirewall;
// import org.springframework.security.web.access.AccessDeniedHandler;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Autowired
// private CustomAccessDeniedHandler accessDeniedHandler;

// @Autowired
// private CustomAuthenticationEntryPoint authenticationEntryPoint;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf().disable()
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate", "/logout",
// "/password-reset/request",
// "/password-reset/validate", "/password-reset/reset")
// .permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class)
// .logout(logout -> logout
// .logoutUrl("/logout")
// .logoutSuccessHandler(logoutSuccessHandler()))
// .exceptionHandling()
// .authenticationEntryPoint(authenticationEntryPoint) // Add this line
// .accessDeniedHandler(accessDeniedHandler); // Add this line

// // Apply the custom HttpFirewall
// http.apply(new CustomHttpFirewallConfigurer());

// return http.build();
// }

// @Bean
// public LogoutSuccessHandler logoutSuccessHandler() {
// return (request, response, authentication) -> {
// String authHeader = request.getHeader("Authorization");
// if (authHeader != null && authHeader.startsWith("Bearer ")) {
// String jwtToken = authHeader.substring(7);
// blacklistedTokenRepository.save(new BlacklistedToken(jwtToken));
// }
// response.setStatus(HttpServletResponse.SC_OK);
// response.setContentType("application/json");
// response.getWriter().write("{ \"message\": \"You have been logged out
// successfully.\" }");
// };
// }

// @Bean
// public HttpFirewall strictHttpFirewall() {
// StrictHttpFirewall firewall = new StrictHttpFirewall();
// firewall.setAllowUrlEncodedSlash(true);
// firewall.setAllowSemicolon(true);
// firewall.setAllowUrlEncodedPercent(true);
// firewall.setAllowBackSlash(true);
// firewall.setAllowUrlEncodedPeriod(true);
// return firewall;
// }

// public class CustomHttpFirewallConfigurer
// extends AbstractHttpConfigurer<CustomHttpFirewallConfigurer, HttpSecurity> {
// @Override
// public void init(HttpSecurity http) throws Exception {
// http.setSharedObject(HttpFirewall.class, strictHttpFirewall());
// }
// }
// }

// ! End code below is good

// package com.example.matching.config;

// import com.example.matching.model.BlacklistedToken;
// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;

// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import
// org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
// import org.springframework.security.web.firewall.HttpFirewall;
// import org.springframework.security.web.firewall.StrictHttpFirewall;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private CustomAccessDeniedHandler accessDeniedHandler;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf().disable()
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate", "/logout",
// "/password-reset/request",
// "/password-reset/validate", "/password-reset/reset")
// .permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class)
// .logout(logout -> logout
// .logoutUrl("/logout")
// .logoutSuccessHandler(logoutSuccessHandler()))
// .exceptionHandling().accessDeniedHandler(accessDeniedHandler); // Add this
// line

// // Apply the custom HttpFirewall
// http.apply(new CustomHttpFirewallConfigurer());

// return http.build();
// }

// @Bean
// public LogoutSuccessHandler logoutSuccessHandler() {
// return (request, response, authentication) -> {
// String authHeader = request.getHeader("Authorization");
// if (authHeader != null && authHeader.startsWith("Bearer ")) {
// String jwtToken = authHeader.substring(7);
// blacklistedTokenRepository.save(new BlacklistedToken(jwtToken));
// }
// response.setStatus(HttpServletResponse.SC_OK);
// response.setContentType("application/json");
// response.getWriter().write("{ \"message\": \"You have been logged out
// successfully.\" }");
// };
// }

// @Bean
// public HttpFirewall strictHttpFirewall() {
// StrictHttpFirewall firewall = new StrictHttpFirewall();
// firewall.setAllowUrlEncodedSlash(true);
// firewall.setAllowSemicolon(true);
// firewall.setAllowUrlEncodedPercent(true);
// firewall.setAllowBackSlash(true);
// firewall.setAllowUrlEncodedPeriod(true);
// return firewall;
// }

// public class CustomHttpFirewallConfigurer
// extends AbstractHttpConfigurer<CustomHttpFirewallConfigurer, HttpSecurity> {
// @Override
// public void init(HttpSecurity http) throws Exception {
// http.setSharedObject(HttpFirewall.class, strictHttpFirewall());
// }
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.model.BlacklistedToken;
// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;

// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import
// org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
// import org.springframework.security.web.firewall.HttpFirewall;
// import org.springframework.security.web.firewall.StrictHttpFirewall;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf().disable()
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate", "/logout",
// "/password-reset-request",
// "/reset-password")
// .permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class)
// .logout(logout -> logout
// .logoutUrl("/logout")
// .logoutSuccessHandler(logoutSuccessHandler()));

// return http.build();
// }

// @Bean
// public LogoutSuccessHandler logoutSuccessHandler() {
// return (request, response, authentication) -> {
// String authHeader = request.getHeader("Authorization");
// if (authHeader != null && authHeader.startsWith("Bearer ")) {
// String jwtToken = authHeader.substring(7);
// blacklistedTokenRepository.save(new BlacklistedToken(jwtToken));
// }
// response.setStatus(HttpServletResponse.SC_OK);
// response.setContentType("application/json");
// response.getWriter().write("{ \"message\": \"You have been logged out
// successfully.\" }");
// };
// }
// }

// ? End

// // SecurityConfig.java
// package com.example.matching.config;

// import com.example.matching.model.BlacklistedToken;
// import com.example.matching.repository.BlacklistedTokenRepository;
// import com.example.matching.service.CustomUserDetailsService;

// import jakarta.servlet.http.HttpServletResponse;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
// import
// org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private BlacklistedTokenRepository blacklistedTokenRepository;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf().disable()
// .authorizeHttpRequests(authz -> authz
// // .requestMatchers("/register", "/authenticate", "/logout").permitAll()
// .requestMatchers("/register", "/authenticate", "/logout",
// "/api/auth/forgot-password", "/api/auth/reset-password").permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class)
// .logout(logout -> logout
// .logoutUrl("/logout")
// .logoutSuccessHandler(logoutSuccessHandler())
// );

// return http.build();
// }

// @Bean
// public LogoutSuccessHandler logoutSuccessHandler() {
// return (request, response, authentication) -> {
// String authHeader = request.getHeader("Authorization");
// if (authHeader != null && authHeader.startsWith("Bearer ")) {
// String jwtToken = authHeader.substring(7);
// blacklistedTokenRepository.save(new BlacklistedToken(jwtToken));
// }
// response.setStatus(HttpServletResponse.SC_OK);
// response.setContentType("application/json");
// response.getWriter().write("{ \"message\": \"You have been logged out
// successfully.\" }");
// };
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.exception.CustomExceptionHandler;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private CustomExceptionHandler customExceptionHandler;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate").permitAll()
// .anyRequest().authenticated())
// .exceptionHandling().authenticationEntryPoint(customExceptionHandler).and()
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// todo End

// package com.example.matching.config;

// import com.example.matching.exception.CustomExceptionHandler;
// import com.example.matching.service.CustomUserDetailsService;
// import com.example.matching.util.JwtRequestFilter;

// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private CustomExceptionHandler customExceptionHandler;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate", "/logout").permitAll()
// .anyRequest().authenticated())
// .exceptionHandling()
// .authenticationEntryPoint(customExceptionHandler)
// .accessDeniedHandler(customExceptionHandler) // Add this to handle access
// denied exceptions
// .and()
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.exception.CustomExceptionHandler;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private CustomExceptionHandler customExceptionHandler;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate", "/logout").permitAll()
// .anyRequest().authenticated())
// .exceptionHandling().authenticationEntryPoint(customExceptionHandler).and()
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.exception.CustomExceptionHandler;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private CustomExceptionHandler customExceptionHandler;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate", "/logout").permitAll()
// .anyRequest().authenticated())
// .exceptionHandling()
// .authenticationEntryPoint(customExceptionHandler)
// .accessDeniedHandler(customExceptionHandler)
// .and()
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// ? End

// package com.example.matching.config;

// import com.example.matching.exception.CustomExceptionHandler;
// import com.example.matching.service.CustomUserDetailsService;
// // import com.example.matching.util.JwtRequestFilter;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private CustomExceptionHandler customExceptionHandler;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate", "/logout").permitAll()
// .anyRequest().authenticated())
// .exceptionHandling()
// .authenticationEntryPoint(customExceptionHandler)
// .accessDeniedHandler(customExceptionHandler) // Add this to handle access
// denied exceptions
// .and()
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// ! End

// package com.example.matching.config;

// import com.example.matching.exception.CustomExceptionHandler;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private CustomExceptionHandler customExceptionHandler;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate").permitAll()
// .anyRequest().authenticated())
// .exceptionHandling().authenticationEntryPoint(customExceptionHandler).and()
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }
// ! End

// // SecurityConfig.java
// package com.example.matching.config;

// import com.example.matching.exception.CustomExceptionHandler;
// import com.example.matching.service.CustomUserDetailsService;
// // import com.example.matching.util.JwtRequestFilter;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// // import
// org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
// import
// org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private CustomExceptionHandler customExceptionHandler;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate").permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// package com.example.matching.config;

// import com.example.matching.security.CustomAuthenticationProvider;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate").permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .exceptionHandling(exception -> exception
// .authenticationEntryPoint(jwtAuthenticationEntryPoint))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }

// @Autowired
// public void configureAuthenticationManager(AuthenticationManagerBuilder auth,
// CustomAuthenticationProvider customAuthenticationProvider) throws Exception {
// auth.authenticationProvider(customAuthenticationProvider);
// }
// }

// package com.example.matching.config;

// import com.example.matching.security.CustomAuthenticationProvider;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

// @Autowired
// private CustomAuthenticationProvider customAuthenticationProvider;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate").permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .exceptionHandling(exception -> exception
// .authenticationEntryPoint(jwtAuthenticationEntryPoint))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }

// @Autowired
// public void configureAuthenticationManager(AuthenticationManagerBuilder auth)
// throws Exception {
// auth.authenticationProvider(customAuthenticationProvider);
// }
// }

// // SecurityConfig.java
// package com.example.matching.config;

// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Autowired
// private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate").permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .exceptionHandling(exception -> exception
// .authenticationEntryPoint(jwtAuthenticationEntryPoint))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// import com.example.matching.service.CustomUserDetailsService;
// // import com.example.matching.util.JwtRequestFilter;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.authentication.AuthenticationManager;
// import
// org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import
// org.springframework.security.config.annotation.web.builders.HttpSecurity;
// import
// org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// // import
// org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
// import
// org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
// import
// org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
// import org.springframework.security.config.http.SessionCreationPolicy;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.web.SecurityFilterChain;
// import
// org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// @Configuration
// @EnableWebSecurity
// public class SecurityConfig {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private JwtRequestFilter jwtRequestFilter;

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }

// @Bean
// public AuthenticationManager
// authenticationManager(AuthenticationConfiguration
// authenticationConfiguration)
// throws Exception {
// return authenticationConfiguration.getAuthenticationManager();
// }

// @Bean
// public SecurityFilterChain securityFilterChain(HttpSecurity http) throws
// Exception {
// http.csrf(AbstractHttpConfigurer::disable)
// .authorizeHttpRequests(authz -> authz
// .requestMatchers("/register", "/authenticate").permitAll()
// .anyRequest().authenticated())
// .sessionManagement(session ->
// session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
// .addFilterBefore(jwtRequestFilter,
// UsernamePasswordAuthenticationFilter.class);

// return http.build();
// }
// }

// package com.example.matching.config;

// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.security.crypto.password.PasswordEncoder;

// @Configuration
// public class SecurityConfig {

// @Bean
// public PasswordEncoder passwordEncoder() {
// return new BCryptPasswordEncoder();
// }
// }
