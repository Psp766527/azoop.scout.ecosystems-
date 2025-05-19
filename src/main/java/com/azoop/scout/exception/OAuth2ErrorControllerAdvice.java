package com.azoop.scout.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@ControllerAdvice
public class OAuth2ErrorControllerAdvice {

    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleOAuth2Error(OAuth2AuthenticationException ex, HttpServletRequest request) {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("timestamp", Instant.now());
        response.put("status", HttpStatus.UNAUTHORIZED.value());
        response.put("error", "OAuth2 Authentication Failed");
        response.put("message", ex.getError().getDescription());
        response.put("errorCode", ex.getError().getErrorCode());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
}
