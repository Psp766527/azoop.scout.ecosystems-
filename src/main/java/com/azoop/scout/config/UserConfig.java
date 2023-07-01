package com.azoop.scout.config;

import com.azoop.scout.model.User;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class UserConfig {

    @Bean
    public User user(){
        User user = new User();
        user.setUserName("pradeep");
        user.setPassword("Raj");
        user.setEmail("pk@gmail.com");
        return user;
    }
}
