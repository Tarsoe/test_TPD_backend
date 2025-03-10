// package com.example.matching.config;

// // import jakarta.servlet.ServletException;
// // import jakarta.servlet.http.HttpServletRequest;
// // import jakarta.servlet.http.HttpServletResponse;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import java.io.IOException;

// @Component
// public class CustomAuthenticationEntryPoint extends Http403ForbiddenEntryPoint {

//     @Override
//     public void commence(HttpServletRequest request, HttpServletResponse response,
//             AuthenticationException authException) throws IOException {
//         response.setStatus(HttpServletResponse.SC_FORBIDDEN);
//         response.setContentType("application/json");
//         response.getWriter().write("{ \"error\": \"Forbidden\", \"message\": \"" + authException.getMessage() + "\" }");
//     }
// }
