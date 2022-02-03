package tech.pegasys.signers.aws;

import io.vertx.core.json.JsonObject;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

public class AwsSecretsManager {

  private String secretName;
  private String keyStoreValue;

  public static SecretsManagerClient createSecretsManagerClient(AwsCredentialsProvider awsCredentialsProvider, Region region){

    SecretsManagerClient secretsClient = SecretsManagerClient.builder()
      .credentialsProvider(awsCredentialsProvider)
      .region(region)
      .build();

    return secretsClient;

  }

  public static String requestSecretValue(SecretsManagerClient secretsManagerClient, String secretName){
    try {
      GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
        .secretId(secretName)
        .build();

      GetSecretValueResponse valueResponse = secretsManagerClient.getSecretValue(getSecretValueRequest);

      return valueResponse.secretString();
    }
    catch (SecretsManagerException e){
      System.err.println(e.awsErrorDetails().errorMessage());
      System.exit(1);
    }
    return null;
  }

  public static String extractKeyStoreValue(String secretValue){
    JsonObject secretValueJson = new JsonObject(secretValue);
    String keyStoreValue = secretValueJson.getString("keystore");
    return keyStoreValue;
  }

  public String getKeyStoreValue() { return this.keyStoreValue; }

  public AwsSecretsManager(SecretsManagerClient secretsManagerClient, String secretName){
    this.secretName = secretName;
    String secretValue = requestSecretValue(secretsManagerClient, secretName);
    this.keyStoreValue = extractKeyStoreValue(secretValue);
  }

}
