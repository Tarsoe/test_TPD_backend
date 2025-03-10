// package com.example.matching.exception;

// import org.springframework.web.bind.annotation.ControllerAdvice;
// import org.springframework.web.bind.annotation.ExceptionHandler;
// import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;
// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.web.firewall.RequestRejectedException;

// @ControllerAdvice
// public class CustomExceptionHandler extends ResponseEntityExceptionHandler {

//     @ExceptionHandler(RequestRejectedException.class)
//     public ResponseEntity<Object> handleRequestRejectedException(RequestRejectedException ex) {
//         // Return custom response here
//         return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid request");
//     }
// }

// ! End

// package com.example.matching.exception;

// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class CustomExceptionHandler implements AuthenticationEntryPoint {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException) throws IOException {
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter().write(
// "{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// authException.getMessage() + "\" }");
// }
// }

// ! End

// package com.example.matching.exception;

// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.security.web.access.AccessDeniedHandler;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class CustomExceptionHandler implements AuthenticationEntryPoint,
// AccessDeniedHandler {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException) throws IOException {
// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " +
// authException.getMessage());
// }

// @Override
// public void handle(HttpServletRequest request, HttpServletResponse response,
// org.springframework.security.access.AccessDeniedException
// accessDeniedException) throws IOException {
// response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: " +
// accessDeniedException.getMessage());
// }
// }

// ? End

// package com.example.matching.exception;

// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class CustomExceptionHandler implements AuthenticationEntryPoint {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException) throws IOException {
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter().write(
// "{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// authException.getMessage() + "\" }");
// }
// }

// ! End

// package com.example.matching.exception;

// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.security.web.access.AccessDeniedHandler;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class CustomExceptionHandler implements AuthenticationEntryPoint,
// AccessDeniedHandler {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException) throws IOException {
// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " +
// authException.getMessage());
// }

// @Override
// public void handle(HttpServletRequest request, HttpServletResponse response,
// org.springframework.security.access.AccessDeniedException
// accessDeniedException) throws IOException {
// response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: " +
// accessDeniedException.getMessage());
// }
// }

// ? End

// package com.example.matching.exception;

// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.security.web.access.AccessDeniedHandler;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class CustomExceptionHandler implements AuthenticationEntryPoint,
// AccessDeniedHandler {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException) throws IOException {
// response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: " +
// authException.getMessage());
// }

// @Override
// public void handle(HttpServletRequest request, HttpServletResponse response,
// org.springframework.security.access.AccessDeniedException
// accessDeniedException) throws IOException {
// response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden: " +
// accessDeniedException.getMessage());
// }
// }

// ! End

// package com.example.matching.exception;

// import org.springframework.http.HttpStatus;
// import org.springframework.http.ResponseEntity;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.*;

// // import javax.servlet.http.HttpServletRequest;
// // import javax.servlet.http.HttpServletResponse;
// import java.io.IOException;

// @Component
// public class CustomExceptionHandler implements AuthenticationEntryPoint {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException) throws IOException {
// response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
// response.setContentType("application/json");
// response.getWriter().write(
// "{ \"error\": \"Token expired or invalid\", \"message\": \"" +
// authException.getMessage() + "\" }");
// }
// }
