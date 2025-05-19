package com.azoop.scout.service;

import com.azoop.scout.infrastructure.UserRepository;
import com.azoop.scout.model.Role;
import com.azoop.scout.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = userRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUserName())
                .password(user.getPassword())
                .disabled(!user.isEnabled())
                .accountExpired(!user.isAccountNonExpired())
                .credentialsExpired(!user.isCredentialsNonExpired())
                .accountLocked(!user.isAccountNonLocked())
                .authorities(getAuthorities(user.getRoles()))
                .build();
    }

    private Collection<? extends GrantedAuthority> getAuthorities(Set<Role> roles) {
        return roles.stream()
                .flatMap(role -> {
                    Set<GrantedAuthority> authorities = new HashSet<>();
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getName()));

                    // Add permissions as authorities
                    role.getPermissions().forEach(permission ->
                            authorities.add(new SimpleGrantedAuthority(permission.getName())));

                    return authorities.stream();
                })
                .collect(Collectors.toList());
    }
}
