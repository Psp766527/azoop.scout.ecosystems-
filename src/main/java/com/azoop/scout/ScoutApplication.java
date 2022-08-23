package com.azoop.scout;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * This is the base application class which is entry point of the Application
 */
@SpringBootApplication
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
