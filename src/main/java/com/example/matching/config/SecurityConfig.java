package com.example.matching.config;

import com.example.matching.model.BlacklistedToken;
import com.example.matching.repository.BlacklistedTokenRepository;
import com.example.matching.service.CustomUserDetailsService;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Autowired
    private JwtRequestFilter jwtRequestFilter;

    @Autowired
    private BlacklistedTokenRepository blacklistedTokenRepository;

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
        http.csrf().disable()
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers("/register", "/authenticate", "/logout", "/password-reset/request",
                                "/password-reset/validate", "/password-reset/reset")
                        .permitAll()
                        .anyRequest().authenticated())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtRequestFilter, UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler()));

        // Apply the custom HttpFirewall
        http.apply(new CustomHttpFirewallConfigurer());

        return http.build();
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return (request, response, authentication) -> {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwtToken = authHeader.substring(7);
                blacklistedTokenRepository.save(new BlacklistedToken(jwtToken));
            }
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentType("application/json");
            response.getWriter().write("{ \"message\": \"You have been logged out successfully.\" }");
        };
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

    public class CustomHttpFirewallConfigurer
            extends AbstractHttpConfigurer<CustomHttpFirewallConfigurer, HttpSecurity> {
        @Override
        public void init(HttpSecurity http) throws Exception {
            http.setSharedObject(HttpFirewall.class, strictHttpFirewall());
        }
    }
}

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
