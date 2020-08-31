/*
 * Copyright 2020 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.signers.secp256k1.azure;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.signers.secp256k1.api.Signature;
import tech.pegasys.signers.secp256k1.api.Signer;

import java.math.BigInteger;
import java.security.SignatureException;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

public class AzureKeyVaultSignerTest {

  private static final String clientId = System.getenv("AZURE_CLIENT_ID");
  private static final String clientSecret = System.getenv("AZURE_CLIENT_SECRET");
  private static final String keyVaultName = System.getenv("AZURE_KEY_VAULT_NAME");
  private static final String tenantId = System.getenv("AZURE_TENANT_ID");

  public static final String PUBLIC_KEY_HEX_STRING =
      "09b02f8a5fddd222ade4ea4528faefc399623af3f736be3c44f03e2df22fb792f3931a4d9573d333ca74343305762a753388c3422a86d98b713fc91c1ea04842";
  private final Bytes publicKeyBytes = Bytes.fromHexString(PUBLIC_KEY_HEX_STRING);

  @BeforeAll
  static void preChecks() {
    Assumptions.assumeTrue(
        clientId != null && clientSecret != null && keyVaultName != null && tenantId != null,
        "Ensure Azure env variables are set");
  }

  @Test
  public void azureSignerCanSignTwice() {
    final AzureConfig config =
        new AzureConfig(keyVaultName, "TestKey", "", clientId, clientSecret, tenantId);

    final AzureKeyVaultSignerFactory factory = new AzureKeyVaultSignerFactory();
    final Signer signer = factory.createSigner(config);

    final byte[] dataToHash = "Hello World".getBytes(UTF_8);
    signer.sign(dataToHash);
    signer.sign(dataToHash);
  }

  @Test
  void azureWithoutHashingDoesntHashData() throws SignatureException {
    final AzureConfig config =
        new AzureConfig(keyVaultName, "TestKey", "", clientId, clientSecret, tenantId);

    final AzureKeyVaultSigner nonHashingSigner =
        new AzureKeyVaultSigner(config, publicKeyBytes, false);

    final byte[] dataToSign = "Hello World".getBytes(UTF_8);
    final byte[] preHashedData = Hash.sha3(dataToSign);

    final Signature signature = nonHashingSigner.sign(preHashedData);

    // Determine if Web3j thinks the signature comes from the public key used (really proves
    // that the preHashedData isn't hashed a second time).
    final SignatureData sigData =
        new SignatureData(
            signature.getV().toByteArray(),
            Numeric.toBytesPadded(signature.getR(), 32),
            Numeric.toBytesPadded(signature.getS(), 32));

    final BigInteger recoveredPublicKey = Sign.signedMessageHashToKey(preHashedData, sigData);

    assertThat(recoveredPublicKey).isEqualTo(new BigInteger(publicKeyBytes.toArrayUnsafe()));
  }
}
