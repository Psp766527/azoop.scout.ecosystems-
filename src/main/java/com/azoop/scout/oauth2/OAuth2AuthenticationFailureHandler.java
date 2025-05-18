package com.azoop.scout.oauth2;

import com.azoop.scout.config.AppProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import javax.servlet.http.Cookie;

import static com.azoop.scout.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;
    private final ObjectMapper objectMapper;
    private final AppProperties appProperties;

    @Value("${app.oauth2.failure-url:/oauth2/error}")
    private String defaultFailureUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {

        // 1. Determine target URL from cookies or use default
        String targetUrl = determineTargetUrl(request);

        // 2. Clean up cookies
        HttpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);

        // 3. Handle response based on request type (API vs browser)
        if (isApiRequest(request)) {
            handleApiAuthenticationFailure(response, exception, targetUrl);
        } else {
            handleBrowserAuthenticationFailure(request, response, exception, targetUrl);
        }
    }

    private String determineTargetUrl(HttpServletRequest request) {
        return CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue)
                .filter(this::isAuthorizedRedirectUri)
                .orElse(defaultFailureUrl);
    }

    private void handleApiAuthenticationFailure(HttpServletResponse response,
                                                AuthenticationException exception,
                                                String targetUrl) throws IOException {

        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String errorMessage = exception.getLocalizedMessage();

        if (exception instanceof OAuth2AuthenticationException) {
            OAuth2Error oauth2Error = ((OAuth2AuthenticationException) exception).getError();

            // Handle specific OAuth2 error codes
            if ("invalid_token".equals(oauth2Error.getErrorCode())) {
                status = HttpStatus.FORBIDDEN;
                errorMessage = "Invalid token provided";
            } else if ("access_denied".equals(oauth2Error.getErrorCode())) {
                status = HttpStatus.FORBIDDEN;
                errorMessage = "Access denied by user";
            }
        } else if (exception instanceof InternalAuthenticationServiceException) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
            errorMessage = "An internal error occurred";
        }

        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        OAuth2ErrorResponse errorResponse = OAuth2ErrorResponse.builder()
                .status(status.value())
                .error(status.getReasonPhrase())
                .message(errorMessage)
                .path(targetUrl)
                .timestamp(Instant.now())
                .build();

        objectMapper.writeValue(response.getWriter(), errorResponse);
    }

    private void handleBrowserAuthenticationFailure(HttpServletRequest request,
                                                    HttpServletResponse response,
                                                    AuthenticationException exception,
                                                    String targetUrl) throws IOException {

        // Add error parameter to redirect URL
        String errorUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, errorUrl);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        try {
            URI clientRedirectUri = URI.create(uri);
            return appProperties.getOauth2().getAuthorizedRedirectUris()
                    .stream()
                    .anyMatch(authorizedUri -> {
                        URI authorizedRedirectUri = URI.create(authorizedUri);
                        return authorizedRedirectUri.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                                && authorizedRedirectUri.getPort() == clientRedirectUri.getPort();
                    });
        } catch (IllegalArgumentException ex) {
            logger.error("Invalid redirect URI: " + uri, ex);
            return false;
        }
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/") || path.startsWith("/auth/api/");
    }

    @Data
    @Builder
    private static class OAuth2ErrorResponse {
        private int status;
        private String error;
        private String message;
        private String path;
        private Instant timestamp;
    }
}
