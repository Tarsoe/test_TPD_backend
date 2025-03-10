package com.example.matching.exception;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException authException) throws IOException {
        Exception exception = (Exception) request.getAttribute("exception");

        if (exception instanceof UsernameNotFoundException) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, exception.getMessage());
        } else {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "Full authentication is required to access this resource");
        }
    }
}

// ! End

// package com.example.matching.exception;

// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.stereotype.Component;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// import java.io.IOException;

// @Component
// public class CustomAuthenticationEntryPoint implements
// AuthenticationEntryPoint {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException)
// throws IOException {
// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
// response.setContentType("application/json");
// response.getWriter().write("{ \"error\": \"Forbidden\", \"message\": \"" +
// authException.getMessage() + "\" }");
// }
// }

// ! End

// package com.example.matching.exception;

// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;
// import org.springframework.security.core.AuthenticationException;
// import org.springframework.security.web.AuthenticationEntryPoint;
// import org.springframework.stereotype.Component;

// import java.io.IOException;

// @Component
// public class CustomAuthenticationEntryPoint implements
// AuthenticationEntryPoint {

// @Override
// public void commence(HttpServletRequest request, HttpServletResponse
// response,
// AuthenticationException authException)
// throws IOException {
// response.setStatus(HttpServletResponse.SC_FORBIDDEN);
// response.setContentType("application/json");
// response.getWriter().write("{ \"error\": \"Forbidden\", \"message\": \"" +
// authException.getMessage() + "\" }");
// }
// }
