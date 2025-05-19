package com.azoop.scout.components.jwt;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JwtAuthenticationResponse {

    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("token_type")
    private String tokenType = "Bearer";

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("issued_at")
    private Instant issuedAt;

    @JsonProperty("refresh_token")
    private String refreshToken;  // Optional, if you implement refresh tokens

    // Constructor without refresh token
    public JwtAuthenticationResponse(String accessToken, Long expiresIn) {
        this.accessToken = accessToken;
        this.tokenType = "Bearer";
        this.expiresIn = expiresIn;
        this.issuedAt = Instant.now();
    }

    // Static factory method
    public static JwtAuthenticationResponse of(String accessToken, Long expiresIn) {
        return new JwtAuthenticationResponse(accessToken, expiresIn);
    }

    // Builder pattern (optional)
    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String accessToken;
        private Long expiresIn;
        private String refreshToken;

        public Builder accessToken(String accessToken) {
            this.accessToken = accessToken;
            return this;
        }

        public Builder expiresIn(Long expiresIn) {
            this.expiresIn = expiresIn;
            return this;
        }

        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public JwtAuthenticationResponse build() {
            JwtAuthenticationResponse response = new JwtAuthenticationResponse();
            response.setAccessToken(accessToken);
            response.setTokenType("Bearer");
            response.setExpiresIn(expiresIn);
            response.setIssuedAt(Instant.now());
            response.setRefreshToken(refreshToken);
            return response;
        }
    }
}
