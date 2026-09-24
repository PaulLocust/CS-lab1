package ru.paullocust.secureapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** Точка входа приложения. */
@SpringBootApplication
@ConfigurationPropertiesScan
public class SecureApiApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureApiApplication.class, args);
    }
}
