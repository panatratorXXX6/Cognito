package com.example.cognito.utils;

import com.amazonaws.auth.SystemPropertiesCredentialsProvider;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentity;
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClientBuilder;
import com.amazonaws.services.cognitoidentity.model.*;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthRequest;
import com.amazonaws.services.cognitoidp.model.AdminInitiateAuthResult;
import com.amazonaws.services.cognitoidp.model.AuthFlowType;
import com.amazonaws.services.cognitoidp.model.RespondToAuthChallengeRequest;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class CognitoUtils {
    private static String clientId = "91j458vae94drghnphnme6usl";
    private static String userPoolId = "eu-central-1_rPf2uAC7M";
    private static String region = "eu-central-1";

    private static String providerName = "cognito-idp.eu-central-1.amazonaws.com/eu-central-1_rPf2uAC7M";
    private static String identityPoolId = "eu-central-1:4cce6f69-7b41-4218-99fe-a9f53ba1c063";

    private static String userName = "oleg";
    private static String userPassword = "VitaminC12#";
    private static String newUserPassword = "VitaminC12#";

    public static String getIdToken() {
        System.setProperty("aws.accessKeyId", "AKIA6KX5QUL7MP5JFRVP");
        System.setProperty("aws.secretKey", "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");

        AWSCognitoIdentityProvider provider = AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(region)
                .withCredentials(new SystemPropertiesCredentialsProvider())
                .build();

        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", userName);
        authParams.put("PASSWORD", userPassword);

        AdminInitiateAuthRequest adminInitiateAuthRequest = new AdminInitiateAuthRequest()
                .withClientId(clientId)
                .withUserPoolId(userPoolId)
                .withAuthFlow(AuthFlowType.ADMIN_NO_SRP_AUTH)
                .withAuthParameters(authParams);

        AdminInitiateAuthResult result = provider.adminInitiateAuth(adminInitiateAuthRequest);

        System.out.println("result.getChallengeName(): " + result.getChallengeName());

        if (StringUtils.isEmpty(result.getChallengeName())) {
            return result.getAuthenticationResult().getIdToken();
        } else {
            resetPassword(userName, newUserPassword, result, provider);
        }

        return "";
    }

    private static void resetPassword(String userName, String newUserPassword, AdminInitiateAuthResult result, AWSCognitoIdentityProvider provider) {
        Map<String, String> challengeResponses = new HashMap<>();
        challengeResponses.put("USERNAME", userName);
        challengeResponses.put("NEW_PASSWORD", newUserPassword);

        RespondToAuthChallengeRequest respondToAuthChallengeRequest = new RespondToAuthChallengeRequest()
                .withChallengeName("NEW_PASSWORD_REQUIRED")
                .withClientId(clientId)
                .withChallengeResponses(challengeResponses)
                .withSession(result.getSession());

        provider.respondToAuthChallenge(respondToAuthChallengeRequest);
        System.out.println("password reset successfully");
    }

    public static Map<String, Object> getAWSCredentials(String idToken) {
        GetIdRequest idRequest = new GetIdRequest();
        idRequest.setIdentityPoolId(identityPoolId);

        Map<String, String> providerTokens = new HashMap<>();
        providerTokens.put(providerName, idToken);
        idRequest.setLogins(providerTokens);
        System.out.println("providerTokens: " + providerTokens);

        AmazonCognitoIdentity amazonCognitoIdentity = AmazonCognitoIdentityClientBuilder
                .standard()
                .withCredentials(new SystemPropertiesCredentialsProvider())
                .withRegion(region)
                .build();

        GetIdResult idResult = amazonCognitoIdentity.getId(idRequest);
        System.out.println("Identity: " + idResult.getIdentityId());

        GetCredentialsForIdentityResult credentialsForIdentityResult = amazonCognitoIdentity
                .getCredentialsForIdentity(new GetCredentialsForIdentityRequest()
                        .withIdentityId(idResult.getIdentityId())
                        .withLogins(providerTokens));

        Credentials credentials = credentialsForIdentityResult.getCredentials();

        System.out.println("credentials.getAccessKeyId(): " + credentials.getAccessKeyId());
        System.out.println("credentials.getSecretKey(): " + credentials.getSecretKey());
        System.out.println("credentials.getSessionToken(): " + credentials.getSessionToken());

        Map<String, Object> results = new HashMap<>();
        results.put("identityId", idResult.getIdentityId());
        results.put("credentials", credentials);

        return results;
    }
}
