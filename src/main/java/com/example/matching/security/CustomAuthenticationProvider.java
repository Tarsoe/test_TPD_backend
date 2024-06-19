// package com.example.matching.security;

// import com.example.matching.model.User;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.authentication.AuthenticationProvider;
// import org.springframework.security.authentication.BadCredentialsException;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.stereotype.Component;

// import java.util.Set;
// import java.util.stream.Collectors;

// @Component
// public class CustomAuthenticationProvider implements AuthenticationProvider {

//     private final CustomUserDetailsService userDetailsService;
//     private final PasswordEncoder passwordEncoder;

//     @Autowired
//     public CustomAuthenticationProvider(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
//         this.userDetailsService = userDetailsService;
//         this.passwordEncoder = passwordEncoder;
//     }

//     @Override
//     public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//         String usernameOrEmail = authentication.getName();
//         String password = (String) authentication.getCredentials();

//         User user = null;
//         try {
//             user = userDetailsService.loadUserEntityByUsername(usernameOrEmail);
//         } catch (UsernameNotFoundException ex) {
//             try {
//                 user = userDetailsService.loadUserEntityByEmail(usernameOrEmail);
//             } catch (UsernameNotFoundException emailEx) {
//                 throw new UsernameNotFoundException("Email incorrect");
//             }
//         }

//         if (user == null) {
//             throw new UsernameNotFoundException("Username incorrect");
//         }

//         if (!passwordEncoder.matches(password, user.getPassword())) {
//             throw new BadCredentialsException("Password incorrect");
//         }

//         Set<GrantedAuthority> authorities = user.getRoles().stream()
//                 .map(SimpleGrantedAuthority::new)
//                 .collect(Collectors.toSet());

//         return new UsernamePasswordAuthenticationToken(user.getUsername(), password, authorities);
//     }

//     @Override
//     public boolean supports(Class<?> authentication) {
//         return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
//     }
// }



// package com.example.matching.security;

// import com.example.matching.model.User;
// import com.example.matching.service.CustomUserDetailsService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.security.authentication.AuthenticationProvider;
// import org.springframework.security.authentication.BadCredentialsException;
// import
// org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.authority.SimpleGrantedAuthority;
// import
// org.springframework.security.core.userdetails.UsernameNotFoundException;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.stereotype.Component;

// import java.util.Set;
// import java.util.stream.Collectors;

// @Component
// public class CustomAuthenticationProvider implements AuthenticationProvider {

// @Autowired
// private CustomUserDetailsService userDetailsService;

// @Autowired
// private PasswordEncoder passwordEncoder;

// @Override
// public Authentication authenticate(Authentication authentication) throws
// AuthenticationException {
// String usernameOrEmail = authentication.getName();
// String password = (String) authentication.getCredentials();

// User user = null;
// try {
// user = userDetailsService.loadUserEntityByUsername(usernameOrEmail);
// } catch (UsernameNotFoundException ex) {
// try {
// user = userDetailsService.loadUserEntityByEmail(usernameOrEmail);
// } catch (UsernameNotFoundException emailEx) {
// throw new UsernameNotFoundException("Email incorrect");
// }
// }

// if (user == null) {
// throw new UsernameNotFoundException("Username incorrect");
// }

// if (!passwordEncoder.matches(password, user.getPassword())) {
// throw new BadCredentialsException("Password incorrect");
// }

// Set<GrantedAuthority> authorities = user.getRoles().stream()
// .map(SimpleGrantedAuthority::new)
// .collect(Collectors.toSet());

// return new UsernamePasswordAuthenticationToken(user.getUsername(), password,
// authorities);
// }

// @Override
// public boolean supports(Class<?> authentication) {
// return
// UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
// }
// }
