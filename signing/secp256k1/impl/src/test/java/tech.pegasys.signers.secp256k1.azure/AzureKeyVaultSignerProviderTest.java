/*
 * Copyright 2019 ConsenSys AG.
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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
public class AzureKeyVaultSignerProviderTest {

  @Test
  public void generatedSignerHasExpectedAddress() {
    /*
    final ECKeyPair web3jKeyPair = ECKeyPair.create(BigInteger.valueOf(5));

    final AzureConfig config =
        new AzureConfig(
            "arbitraryKeyVault", "keyName", "keyVersion", "clientId", "clientSecret", "tenantId");

    final KeyVaultClient mockClient = mock(KeyVaultClient.class);
    final KeyBundle mockKeyBundle = mock(KeyBundle.class);
    final JsonWebKey mockWebKey = mock(JsonWebKey.class);

    when(mockWebKey.x())
        .thenReturn(Arrays.copyOfRange(web3jKeyPair.getPublicKey().toByteArray(), 0, 32));
    when(mockWebKey.y())
        .thenReturn(Arrays.copyOfRange(web3jKeyPair.getPublicKey().toByteArray(), 32, 64));
    when(mockClient.getKey(any())).thenReturn(mockKeyBundle);
    when(mockKeyBundle.key()).thenReturn(mockWebKey);

    final AzureKeyVaultSignerFactory factory = new AzureKeyVaultSignerFactory();

    final Signer signer = factory.createSigner(config);
    assertThat(signer.getPublicKey().toString())
        .isEqualTo(Numeric.toHexStringWithPrefix(web3jKeyPair.getPublicKey()));
     */
  }
}
