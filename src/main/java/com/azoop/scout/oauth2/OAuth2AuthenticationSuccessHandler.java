package com.azoop.scout.oauth2;

import com.azoop.scout.components.jwt.JwtTokenProvider;
import com.azoop.scout.config.AppProperties;
import com.azoop.scout.exception.BadRequestException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static com.azoop.scout.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;
import javax.servlet.http.Cookie;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final AppProperties appProperties;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        String targetUrl = determineTargetUrl(request, response, authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }

        // Clear authentication attributes from cookies
        clearAuthenticationAttributes(request, response);

        // Get the JWT token
        String token = tokenProvider.generateToken((UserDetails) authentication.getPrincipal());

        // Add token to response (cookie or header)
        addTokenToResponse(request, response, token);

        // Redirect (or return JSON response for API clients)
        if (isApiRequest(request)) {
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(createSuccessResponse(token, targetUrl));
        } else {
            getRedirectStrategy().sendRedirect(request, response, targetUrl);
        }
    }

    protected String determineTargetUrl(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {

        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(Cookie::getValue);

        if (redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("Unauthorized Redirect URI");
        }

        String targetUrl = redirectUri.orElse(getDefaultTargetUrl());

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        if (authentication.getPrincipal() instanceof DefaultOAuth2User) {
            DefaultOAuth2User oauthUser = (DefaultOAuth2User) authentication.getPrincipal();
            params.add("name", oauthUser.getAttribute("name"));
            params.add("email", oauthUser.getAttribute("email"));
        }

        return UriComponentsBuilder.fromUriString(targetUrl)
                .queryParams(params)
                .build().toUriString();
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request,
                                                 HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        HttpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private void addTokenToResponse(HttpServletRequest request,
                                    HttpServletResponse response,
                                    String token) {

        // For API clients, add to Authorization header
        if (isApiRequest(request)) {
            response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        }

        // For browser clients, add as cookie
        CookieUtils.addCookie(response,
                "access_token",
                token,
                (int) (appProperties.getAuth().getTokenExpirationMsec() / 1000));

        // Optionally add refresh token if you implement refresh tokens
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        URI clientRedirectUri = URI.create(uri);

        return appProperties.getOauth2().getAuthorizedRedirectUris()
                .stream()
                .anyMatch(authorizedRedirectUri -> {
                    URI authorizedURI = URI.create(authorizedRedirectUri);
                    return authorizedURI.getHost().equalsIgnoreCase(clientRedirectUri.getHost())
                            && authorizedURI.getPort() == clientRedirectUri.getPort();
                });
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/") || path.startsWith("/auth/api/");
    }

    private String createSuccessResponse(String token, String targetUrl) {
        Map<String, Object> responseData = new HashMap<>();
        responseData.put("token", token);
        responseData.put("redirectUrl", targetUrl);
        responseData.put("tokenType", "Bearer");
        responseData.put("expiresIn", tokenProvider.getTokenExpirationInSeconds());

        try {
            return new ObjectMapper().writeValueAsString(responseData);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Error generating success response");
        }
    }
}