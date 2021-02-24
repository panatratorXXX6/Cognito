package com.example.cognito;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import static com.example.cognito.utils.CognitoUtils.getAWSCredentials;
import static com.example.cognito.utils.CognitoUtils.getIdToken;

@SpringBootApplication
public class CognitoApplication {
	public static void main(String[] args) {
		SpringApplication.run(CognitoApplication.class, args);

		String idToken = getIdToken();
		System.out.println("idToken: " + idToken);
		getAWSCredentials(idToken);
	}
}
