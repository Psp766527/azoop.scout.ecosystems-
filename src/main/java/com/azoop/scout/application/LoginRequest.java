package com.azoop.scout.application;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Username or Email is required")
    @Size(min = 3, max = 60, message = "Username/Email must be between 3 and 60 characters")
    private String userNameOrEmail;

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 40, message = "Password must be between 6 and 40 characters")
    private String password;

    private boolean rememberMe = false; // Optional: for "remember me" functionality
}
