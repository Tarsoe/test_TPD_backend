package com.example.matching.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.*;

import com.example.matching.config.HashUtil;
import com.example.matching.service.CustomUserDetails;

@Component
public class JwtTokenUtil {

    // private String secret = "your_secret_key"; // Use a strong secret key and
    // keep it secure
    // // Alternatively, use Spring’s Environment abstraction:
    // @Value("${jwt.secret}")
    // private String secret;
    @Value("${JWT_SECRET}")
    private String secret;

    // In-memory token blacklist (consider using Redis or a database in a real-world
    // application)
    private Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

    // Retrieve username from jwt token
    public String getUsernameFromToken(String token) {
        return getClaimFromToken(token, Claims::getSubject);
    }

    // Retrieve email from jwt token
    public String getEmailFromToken(String token) {
        return getAllClaimsFromToken(token).get("email", String.class);
    }

    // Retrieve user ID from jwt token
    // public UUID getUserIdFromToken(String token) {
    // return getAllClaimsFromToken(token).get("userId", UUID.class);
    // }
    // public UUID getUserIdFromToken(String token) {
    // String userId = getClaimFromToken(token, Claims::getSubject);
    // System.out.println("User ID extracted from token: " + userId);
    // return UUID.fromString(userId);
    // }
    public UUID getUserIdFromToken(String token) {
        String userIdString = getClaimFromToken(token, claims -> claims.get("userId", String.class)); // Retrieve as
        System.out.println("User ID extracted from token: " + userIdString); // String
        return UUID.fromString(userIdString); // Convert String back to UUID
    }

    // Retrieve expiration date from jwt token
    public Date getExpirationDateFromToken(String token) {
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    // For retrieving any information from token we will need the secret key
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }

    // Check if the token has expired
    private Boolean isTokenExpired(String token) {
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    // Generate token for user
    // public String generateToken(UserDetails userDetails, String email, UUID
    // userId) {
    // Map<String, Object> claims = new HashMap<>();
    // claims.put("email", email);
    // claims.put("userId", userId);
    // return doGenerateToken(claims, userDetails.getUsername());
    // }
    // public String generateToken(UserDetails userDetails, String email, UUID
    // userId) {
    // Map<String, Object> claims = new HashMap<>();
    // claims.put("email", email);
    // claims.put("userId", userId.toString()); // Store UUID as String
    // return doGenerateToken(claims, userDetails.getUsername());
    // }

    // * Generate token for user with only userId and no subject
    // public String generateToken(UserDetails userDetails, UUID userId) {
    // Map<String, Object> claims = new HashMap<>();
    // claims.put("userId", userId.toString()); // Store UUID as String
    // return doGenerateToken(claims, ""); // No subject
    // }

    // ? Generate token for user with only userId
    public String generateToken(UserDetails userDetails, UUID userId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId.toString()); // Store UUID as String
        return doGenerateToken(claims, userId.toString()); // Use userId as the subject, or pass an empty string if you
                                                           // // don't need a subject
    }

    // While creating the token -
    // 1. Define claims of the token, like Issuer, Expiration, Subject, and the ID
    // 2. Sign the JWT using the HS512 algorithm and secret key.
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                // .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000))
                .setExpiration(new Date(System.currentTimeMillis() + 60 * 1000)) //? 1 minute
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    // Validate token
    public Boolean validateToken(String token, UserDetails userDetails) {
        final UUID userIdFromToken = getUserIdFromToken(token);
        final UUID userIdFromUserDetails = ((CustomUserDetails) userDetails).getUserId();

        return (userIdFromToken.equals(userIdFromUserDetails) && !isTokenExpired(token) && !isTokenBlacklisted(token));
    }

    // Invalidate token
    // public void invalidateToken(String token) {
    // tokenBlacklist.add(token);
    // }
    public void invalidateToken(String token) {
        String hashedToken = HashUtil.hashToken(token); // Hash the JWT token
        tokenBlacklist.add(hashedToken); // Add the hashed token to the blacklist
    }

    // Check if token is blacklisted
    public boolean isTokenBlacklisted(String token) {
        return tokenBlacklist.contains(token);
    }

    public Boolean isTokenAboutToExpire(String token, int thresholdInMinutes) {
        final Date expiration = getExpirationDateFromToken(token);
        Date now = new Date();
        long diffInMillies = expiration.getTime() - now.getTime();
        long diffInMinutes = TimeUnit.MILLISECONDS.toMinutes(diffInMillies);
        return diffInMinutes < thresholdInMinutes;
    }

}

// ! Still long id
// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.Set;
// import java.util.concurrent.ConcurrentHashMap;
// import java.util.function.Function;

// import com.example.matching.service.CustomUserDetails;

// @Component
// public class JwtTokenUtil {

// private String secret = "your_secret_key"; // Use a strong secret key and
// keep it secure

// // In-memory token blacklist (consider using Redis or a database in a
// real-world
// // application)
// private Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

// // Retrieve username from jwt token
// public String getUsernameFromToken(String token) {
// return getClaimFromToken(token, Claims::getSubject);
// }

// // Retrieve email from jwt token
// public String getEmailFromToken(String token) {
// return getAllClaimsFromToken(token).get("email", String.class);
// }

// // Retrieve user ID from jwt token
// public Long getUserIdFromToken(String token) {
// return getAllClaimsFromToken(token).get("userId", Long.class);
// }

// // Retrieve expiration date from jwt token
// public Date getExpirationDateFromToken(String token) {
// return getClaimFromToken(token, Claims::getExpiration);
// }

// public <T> T getClaimFromToken(String token, Function<Claims, T>
// claimsResolver) {
// final Claims claims = getAllClaimsFromToken(token);
// return claimsResolver.apply(claims);
// }

// // For retrieving any information from token we will need the secret key
// private Claims getAllClaimsFromToken(String token) {
// return Jwts.parser()
// .setSigningKey(secret)
// .parseClaimsJws(token)
// .getBody();
// }

// // Check if the token has expired
// private Boolean isTokenExpired(String token) {
// final Date expiration = getExpirationDateFromToken(token);
// return expiration.before(new Date());
// }

// // Generate token for user
// public String generateToken(UserDetails userDetails, String email, Long
// userId) {
// Map<String, Object> claims = new HashMap<>();
// claims.put("email", email);
// claims.put("userId", userId);
// return doGenerateToken(claims, userDetails.getUsername());
// }

// // While creating the token -
// // 1. Define claims of the token, like Issuer, Expiration, Subject, and the
// ID
// // 2. Sign the JWT using the HS512 algorithm and secret key.
// private String doGenerateToken(Map<String, Object> claims, String subject) {
// return Jwts.builder()
// .setClaims(claims)
// .setSubject(subject)
// .setIssuedAt(new Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000))
// .signWith(SignatureAlgorithm.HS512, secret)
// .compact();
// }

// // Validate token
// // public Boolean validateToken(String token, UserDetails userDetails) {
// // final String username = getUsernameFromToken(token);
// // return (username.equals(userDetails.getUsername()) &&
// !isTokenExpired(token) && !isTokenBlacklisted(token));
// // }
// public Boolean validateToken(String token, UserDetails userDetails) {
// final Long userIdFromToken = Long.valueOf(getUserIdFromToken(token));
// final Long userIdFromUserDetails = ((CustomUserDetails)
// userDetails).getUserId();
// return (userIdFromToken.equals(userIdFromUserDetails) &&
// !isTokenExpired(token) && !isTokenBlacklisted(token));
// }

// // Invalidate token
// public void invalidateToken(String token) {
// tokenBlacklist.add(token);
// }

// // Check if token is blacklisted
// public boolean isTokenBlacklisted(String token) {
// return tokenBlacklist.contains(token);
// }
// }

// ! Below is userId is String

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.Set;
// import java.util.concurrent.ConcurrentHashMap;
// import java.util.function.Function;

// @Component
// public class JwtTokenUtil {

// private String secret = "your_secret_key"; // Use a strong secret key and
// keep it secure

// // In-memory token blacklist (consider using Redis or a database in a
// real-world
// // application)
// private Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

// // Retrieve username from jwt token
// public String getUsernameFromToken(String token) {
// return getClaimFromToken(token, Claims::getSubject);
// }

// // Retrieve email from jwt token
// public String getEmailFromToken(String token) {
// return getAllClaimsFromToken(token).get("email", String.class);
// }

// // Retrieve user ID from jwt token
// public Long getUserIdFromToken(String token) {
// return getAllClaimsFromToken(token).get("userId", Long.class);
// }

// // Retrieve expiration date from jwt token
// public Date getExpirationDateFromToken(String token) {
// return getClaimFromToken(token, Claims::getExpiration);
// }

// public <T> T getClaimFromToken(String token, Function<Claims, T>
// claimsResolver) {
// final Claims claims = getAllClaimsFromToken(token);
// return claimsResolver.apply(claims);
// }

// // For retrieving any information from token we will need the secret key
// private Claims getAllClaimsFromToken(String token) {
// return Jwts.parser()
// .setSigningKey(secret)
// .parseClaimsJws(token)
// .getBody();
// }

// // Check if the token has expired
// private Boolean isTokenExpired(String token) {
// final Date expiration = getExpirationDateFromToken(token);
// return expiration.before(new Date());
// }

// // Generate token for user
// public String generateToken(UserDetails userDetails, String email, String
// userId) {
// Map<String, Object> claims = new HashMap<>();
// claims.put("email", email);
// claims.put("userId", userId);
// return doGenerateToken(claims, userDetails.getUsername());
// }

// // While creating the token -
// // 1. Define claims of the token, like Issuer, Expiration, Subject, and the
// ID
// // 2. Sign the JWT using the HS512 algorithm and secret key.
// private String doGenerateToken(Map<String, Object> claims, String subject) {
// return Jwts.builder()
// .setClaims(claims)
// .setSubject(subject)
// .setIssuedAt(new Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000))
// // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 1))
// .signWith(SignatureAlgorithm.HS512, secret)
// .compact();
// }

// // Validate token
// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = getUsernameFromToken(token);
// return (username.equals(userDetails.getUsername()) && !isTokenExpired(token)
// && !isTokenBlacklisted(token));
// }

// // Invalidate token
// public void invalidateToken(String token) {
// tokenBlacklist.add(token);
// }

// // Check if token is blacklisted
// public boolean isTokenBlacklisted(String token) {
// return tokenBlacklist.contains(token);
// }
// }

// ! Below is good

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.Set;
// import java.util.concurrent.ConcurrentHashMap;
// import java.util.function.Function;

// @Component
// public class JwtTokenUtil {

// private String secret = "your_secret_key"; // Use a strong secret key and
// keep it secure

// // In-memory token blacklist (consider using Redis or a database in a
// real-world
// // application)
// private Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

// // Retrieve username from jwt token
// public String getUsernameFromToken(String token) {
// return getClaimFromToken(token, Claims::getSubject);
// }

// // Retrieve email from jwt token
// public String getEmailFromToken(String token) {
// return getAllClaimsFromToken(token).get("email", String.class);
// }

// // Retrieve expiration date from jwt token
// public Date getExpirationDateFromToken(String token) {
// return getClaimFromToken(token, Claims::getExpiration);
// }

// public <T> T getClaimFromToken(String token, Function<Claims, T>
// claimsResolver) {
// final Claims claims = getAllClaimsFromToken(token);
// return claimsResolver.apply(claims);
// }

// // For retrieving any information from token we will need the secret key
// private Claims getAllClaimsFromToken(String token) {
// return Jwts.parser()
// .setSigningKey(secret)
// .parseClaimsJws(token)
// .getBody();
// }

// // Check if the token has expired
// private Boolean isTokenExpired(String token) {
// final Date expiration = getExpirationDateFromToken(token);
// return expiration.before(new Date());
// }

// // Generate token for user
// public String generateToken(UserDetails userDetails, String email) {
// Map<String, Object> claims = new HashMap<>();
// claims.put("email", email);
// return doGenerateToken(claims, userDetails.getUsername());
// }

// // While creating the token -
// // 1. Define claims of the token, like Issuer, Expiration, Subject, and the
// ID
// // 2. Sign the JWT using the HS512 algorithm and secret key.
// private String doGenerateToken(Map<String, Object> claims, String subject) {
// return Jwts.builder()
// .setClaims(claims)
// .setSubject(subject)
// .setIssuedAt(new Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 2 * 60 * 60 * 1000))
// // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 1))
// .signWith(SignatureAlgorithm.HS512, secret)
// .compact();
// }

// // Validate token
// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = getUsernameFromToken(token);
// return (username.equals(userDetails.getUsername()) && !isTokenExpired(token)
// && !isTokenBlacklisted(token));
// }

// // Invalidate token
// public void invalidateToken(String token) {
// tokenBlacklist.add(token);
// }

// // Check if token is blacklisted
// public boolean isTokenBlacklisted(String token) {
// return tokenBlacklist.contains(token);
// }
// }

// ! End

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.Set;
// import java.util.concurrent.ConcurrentHashMap;
// import java.util.function.Function;

// @Component
// public class JwtTokenUtil {

// // private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

// private String secret = "your_secret_key"; // Use a strong secret key and
// keep it secure

// // In-memory token blacklist (consider using Redis or a database in a
// real-world
// // application)
// private Set<String> tokenBlacklist = ConcurrentHashMap.newKeySet();

// // Retrieve username from jwt token
// public String getUsernameFromToken(String token) {
// return getClaimFromToken(token, Claims::getSubject);
// }

// // Retrieve expiration date from jwt token
// public Date getExpirationDateFromToken(String token) {
// return getClaimFromToken(token, Claims::getExpiration);
// }

// public <T> T getClaimFromToken(String token, Function<Claims, T>
// claimsResolver) {
// final Claims claims = getAllClaimsFromToken(token);
// return claimsResolver.apply(claims);
// }

// // For retrieving any information from token we will need the secret key
// private Claims getAllClaimsFromToken(String token) {
// return Jwts.parser()
// .setSigningKey(secret)
// .parseClaimsJws(token)
// .getBody();
// }

// // Check if the token has expired
// private Boolean isTokenExpired(String token) {
// final Date expiration = getExpirationDateFromToken(token);
// return expiration.before(new Date());
// }

// // Generate token for user
// public String generateToken(UserDetails userDetails) {
// Map<String, Object> claims = new HashMap<>();
// return doGenerateToken(claims, userDetails.getUsername());
// }

// // While creating the token -
// // 1. Define claims of the token, like Issuer, Expiration, Subject, and the
// ID
// // 2. Sign the JWT using the HS512 algorithm and secret key.
// private String doGenerateToken(Map<String, Object> claims, String subject) {
// return Jwts.builder()
// .setClaims(claims)
// .setSubject(subject)
// .setIssuedAt(new Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 1000 * 30))
// // .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY *
// 1000))
// .signWith(SignatureAlgorithm.HS512, secret)
// .compact();
// }

// // Validate token
// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = getUsernameFromToken(token);
// return (username.equals(userDetails.getUsername()) && !isTokenExpired(token)
// && !isTokenBlacklisted(token));
// }

// // Invalidate token
// public void invalidateToken(String token) {
// tokenBlacklist.add(token);
// }

// // Check if token is blacklisted
// public boolean isTokenBlacklisted(String token) {
// return tokenBlacklist.contains(token);
// }
// }

// ! End

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.function.Function;

// @Component
// public class JwtTokenUtil {

// private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

// private String secret = "your_secret_key"; // Use a strong secret key and
// keep it secure

// // Retrieve username from jwt token
// public String getUsernameFromToken(String token) {
// return getClaimFromToken(token, Claims::getSubject);
// }

// // Retrieve expiration date from jwt token
// public Date getExpirationDateFromToken(String token) {
// return getClaimFromToken(token, Claims::getExpiration);
// }

// public <T> T getClaimFromToken(String token, Function<Claims, T>
// claimsResolver) {
// final Claims claims = getAllClaimsFromToken(token);
// return claimsResolver.apply(claims);
// }

// // For retrieving any information from token we will need the secret key
// private Claims getAllClaimsFromToken(String token) {
// return Jwts.parser()
// .setSigningKey(secret)
// .parseClaimsJws(token)
// .getBody();
// }

// // Check if the token has expired
// private Boolean isTokenExpired(String token) {
// final Date expiration = getExpirationDateFromToken(token);
// return expiration.before(new Date());
// }

// // Generate token for user
// public String generateToken(UserDetails userDetails) {
// Map<String, Object> claims = new HashMap<>();
// return doGenerateToken(claims, userDetails.getUsername());
// }

// // While creating the token -
// // 1. Define claims of the token, like Issuer, Expiration, Subject, and the
// ID
// // 2. Sign the JWT using the HS512 algorithm and secret key.
// private String doGenerateToken(Map<String, Object> claims, String subject) {
// return Jwts.builder()
// .setClaims(claims)
// .setSubject(subject)
// .setIssuedAt(new Date(System.currentTimeMillis()))
// // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 40 ))
// .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY *
// 1000))
// .signWith(SignatureAlgorithm.HS512, secret)
// .compact();
// }

// // Validate token
// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = getUsernameFromToken(token);
// return (username.equals(userDetails.getUsername()) &&
// !isTokenExpired(token));
// }
// }

// ? End

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.function.Function;

// @Component
// public class JwtTokenUtil {

// private static final long JWT_TOKEN_VALIDITY = 5 * 60 * 60;

// private String secret = "your_secret_key"; // Use a strong secret key and
// keep it secure

// // Retrieve username from jwt token
// public String getUsernameFromToken(String token) {
// return getClaimFromToken(token, Claims::getSubject);
// }

// // Retrieve expiration date from jwt token
// public Date getExpirationDateFromToken(String token) {
// return getClaimFromToken(token, Claims::getExpiration);
// }

// public <T> T getClaimFromToken(String token, Function<Claims, T>
// claimsResolver) {
// final Claims claims = getAllClaimsFromToken(token);
// return claimsResolver.apply(claims);
// }

// // For retrieving any information from token we will need the secret key
// private Claims getAllClaimsFromToken(String token) {
// return Jwts.parser()
// .setSigningKey(secret)
// .parseClaimsJws(token)
// .getBody();
// }

// // Check if the token has expired
// private Boolean isTokenExpired(String token) {
// final Date expiration = getExpirationDateFromToken(token);
// return expiration.before(new Date());
// }

// // Generate token for user
// public String generateToken(UserDetails userDetails) {
// Map<String, Object> claims = new HashMap<>();
// return doGenerateToken(claims, userDetails.getUsername());
// }

// // While creating the token -
// // 1. Define claims of the token, like Issuer, Expiration, Subject, and the
// ID
// // 2. Sign the JWT using the HS512 algorithm and secret key.
// private String doGenerateToken(Map<String, Object> claims, String subject) {
// return Jwts.builder()
// .setClaims(claims)
// .setSubject(subject)
// .setIssuedAt(new Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 1000 * 30))
// // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 1))
// // .setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_VALIDITY *
// 1000))
// .signWith(SignatureAlgorithm.HS512, secret)
// .compact();
// }

// // Validate token
// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = getUsernameFromToken(token);
// return (username.equals(userDetails.getUsername()) &&
// !isTokenExpired(token));
// }
// }

// ! End

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.beans.factory.annotation.Value;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.function.Function;

// @Component
// public class JwtTokenUtil {

// @Value("${jwt.secret}")
// private String secret;

// @Value("${jwt.expiration}")
// private Long expiration;

// public String getUsernameFromToken(String token) {
// return getClaimFromToken(token, Claims::getSubject);
// }

// public Date getExpirationDateFromToken(String token) {
// return getClaimFromToken(token, Claims::getExpiration);
// }

// public <T> T getClaimFromToken(String token, Function<Claims, T>
// claimsResolver) {
// final Claims claims = getAllClaimsFromToken(token);
// return claimsResolver.apply(claims);
// }

// private Claims getAllClaimsFromToken(String token) {
// return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
// }

// private Boolean isTokenExpired(String token) {
// final Date expiration = getExpirationDateFromToken(token);
// return expiration.before(new Date());
// }

// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = getUsernameFromToken(token);
// return (username.equals(userDetails.getUsername()) &&
// !isTokenExpired(token));
// }

// public String generateToken(UserDetails userDetails) {
// return Jwts.builder()
// .setSubject(userDetails.getUsername())
// .setIssuedAt(new Date())
// .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
// .signWith(SignatureAlgorithm.HS512, secret)
// .compact();
// }
// }

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Service;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.function.Function;

// @Service
// public class JwtUtil {

// private String SECRET_KEY = "secret";

// public String extractUsername(String token) {
// return extractClaim(token, Claims::getSubject);
// }

// public Date extractExpiration(String token) {
// return extractClaim(token, Claims::getExpiration);
// }

// public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
// final Claims claims = extractAllClaims(token);
// return claimsResolver.apply(claims);
// }

// private Claims extractAllClaims(String token) {
// return
// Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
// }

// private Boolean isTokenExpired(String token) {
// return extractExpiration(token).before(new Date());
// }

// public String generateToken(UserDetails userDetails) {
// Map<String, Object> claims = new HashMap<>();
// return createToken(claims, userDetails.getUsername());
// }

// private String createToken(Map<String, Object> claims, String subject) {
// return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new
// Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 1))
// // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
// .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
// }

// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = extractUsername(token);
// return (username.equals(userDetails.getUsername()) &&
// !isTokenExpired(token));
// }
// }

// // JwtUtil.java
// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Component;

// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.function.Function;

// @Component
// public class JwtUtil {

// private String SECRET_KEY = "secret";

// public String extractUsername(String token) {
// return extractClaim(token, Claims::getSubject);
// }

// public Date extractExpiration(String token) {
// return extractClaim(token, Claims::getExpiration);
// }

// public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
// final Claims claims = extractAllClaims(token);
// return claimsResolver.apply(claims);
// }

// private Claims extractAllClaims(String token) {
// return
// Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
// }

// private Boolean isTokenExpired(String token) {
// return extractExpiration(token).before(new Date());
// }

// public String generateToken(UserDetails userDetails) {
// Map<String, Object> claims = new HashMap<>();
// return createToken(claims, userDetails.getUsername());
// }

// private String createToken(Map<String, Object> claims, String subject) {
// return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new
// Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60))
// // .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
// .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
// }

// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = extractUsername(token);
// return (username.equals(userDetails.getUsername()) &&
// !isTokenExpired(token));
// }
// }

// package com.example.matching.util;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.SignatureAlgorithm;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.stereotype.Service;
// import java.util.Date;
// import java.util.HashMap;
// import java.util.Map;
// import java.util.function.Function;

// @Service
// public class JwtUtil {

// private String SECRET_KEY = "secret";

// public String extractUsername(String token) {
// return extractClaim(token, Claims::getSubject);
// }

// public Date extractExpiration(String token) {
// return extractClaim(token, Claims::getExpiration);
// }

// public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
// final Claims claims = extractAllClaims(token);
// return claimsResolver.apply(claims);
// }

// private Claims extractAllClaims(String token) {
// return
// Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token).getBody();
// }

// private Boolean isTokenExpired(String token) {
// return extractExpiration(token).before(new Date());
// }

// public String generateToken(UserDetails userDetails) {
// Map<String, Object> claims = new HashMap<>();
// return createToken(claims, userDetails.getUsername());
// }

// private String createToken(Map<String, Object> claims, String subject) {

// return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new
// Date(System.currentTimeMillis()))
// .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10))
// .signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
// }

// public Boolean validateToken(String token, UserDetails userDetails) {
// final String username = extractUsername(token);
// return (username.equals(userDetails.getUsername()) &&
// !isTokenExpired(token));
// }
// }
