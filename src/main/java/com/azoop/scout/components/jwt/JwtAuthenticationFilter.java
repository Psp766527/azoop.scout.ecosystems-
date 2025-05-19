package com.azoop.scout.components.jwt;

import com.azoop.scout.service.CustomUserDetailsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider tokenProvider;
    private final CustomUserDetailsService customUserDetailsService;

    public JwtAuthenticationFilter(JwtTokenProvider tokenProvider,
                                   CustomUserDetailsService customUserDetailsService) {
        this.tokenProvider = tokenProvider;
        this.customUserDetailsService = customUserDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {
        try {
            // 1. Get JWT token from request
            String jwt = getJwtFromRequest(request);

            // 2. Validate token
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                // 3. Get username from token
                String username = tokenProvider.getUserNameFromToken(jwt);

                // 4. Load user details from database
                UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

                // 5. Create authentication object
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities());

                // 6. Set details in authentication object
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // 7. Set authentication in Security Context
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            logger.error("Could not set user authentication in security context", ex);

            // You might want to customize the error response here
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

            Map<String, String> errorDetails = new HashMap<>();
            errorDetails.put("message", "Authentication failed");
            errorDetails.put("details", ex.getMessage());
            errorDetails.put("timestamp", Instant.now().toString());

            new ObjectMapper().writeValue(response.getOutputStream(), errorDetails);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        // 1. Get token from Authorization header
        String bearerToken = request.getHeader("Authorization");

        // 2. Check if header contains Bearer token
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }

        // 3. Alternatively, check for token in cookie
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("access_token".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }

        // 4. Or check for token in query parameter
        String token = request.getParameter("token");
        if (StringUtils.hasText(token)) {
            return token;
        }

        return null;
    }
}
