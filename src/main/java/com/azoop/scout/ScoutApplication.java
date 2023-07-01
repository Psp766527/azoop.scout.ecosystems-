package com.azoop.scout;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

/**
 * This is the base application class which is entry point of the Application
 */
@SpringBootApplication
//@EnableAuthorizationServer
//@EnableResourceServer

public class ScoutApplication {

    /**
     * This method will we be helping the application to run.
     *
     * @param args the arguments array.
     */
    public static void main(String[] args) {
        SpringApplication.run(ScoutApplication.class, args);
    }

}
