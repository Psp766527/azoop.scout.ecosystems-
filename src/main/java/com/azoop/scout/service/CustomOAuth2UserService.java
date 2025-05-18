package com.azoop.scout.service;

import com.azoop.scout.infrastructure.RoleRepository;
import com.azoop.scout.infrastructure.UserRepository;
import com.azoop.scout.model.Role;
import com.azoop.scout.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = new DefaultOAuth2UserService().loadUser(userRequest);

        Map<String, Object> attributes = oAuth2User.getAttributes();
        String email = (String) attributes.get("email");

        // Check if user exists in your database
        Optional<User> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            return buildOAuth2User(user, attributes);
        } else {
            // Register new user
            User newUser = registerNewUser(attributes);
            return buildOAuth2User(newUser, attributes);
        }
    }

    private User registerNewUser(Map<String, Object> attributes) {
        User user = User.builder()
                .userName((String) attributes.get("email"))
                .email((String) attributes.get("email"))
                .password(UUID.randomUUID().toString()) // Random password, user will use OAuth to login
                .enabled(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .accountNonLocked(true)
                .build();

        // Assign default role
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));
        user.getRoles().add(userRole);

        return userRepository.save(user);
    }

    private OAuth2User buildOAuth2User(User user, Map<String, Object> attributes) {
        Set<GrantedAuthority> authorities = user.getRoles().stream()
                .flatMap(role -> {
                    Set<GrantedAuthority> auths = new HashSet<>();
                    auths.add(new SimpleGrantedAuthority(role.getName()));
                    role.getPermissions().forEach(permission ->
                            auths.add(new SimpleGrantedAuthority(permission.getName())));
                    return auths.stream();
                })
                .collect(Collectors.toSet());

        return new DefaultOAuth2User(
                authorities,
                attributes,
                "email" // Name of the attribute in the attributes Map that contains the username
        );
    }
}