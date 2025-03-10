package com.example.matching;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.github.cdimascio.dotenv.Dotenv;

@SpringBootApplication
public class MatchingApplication {

	public static void main(String[] args) {

		// Load the .env file
		Dotenv dotenv = Dotenv.load();

		// Make the environment variables available
		dotenv.entries().forEach(entry -> System.setProperty(entry.getKey(), entry.getValue()));

		SpringApplication.run(MatchingApplication.class, args);
	}

}
