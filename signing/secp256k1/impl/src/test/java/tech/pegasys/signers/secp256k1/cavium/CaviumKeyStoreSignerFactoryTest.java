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
package tech.pegasys.signers.secp256k1.cavium;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import tech.pegasys.signers.cavium.CaviumKeyStoreProvider;
import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.signers.secp256k1.api.Signer;

import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.interfaces.ECPublicKey;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.web3j.utils.Numeric;

public class CaviumKeyStoreSignerFactoryTest {

  private static String key =
      "0xaf80b90d25145da28c583359beb47b21796b2fe1a23c1511e443e7a64dfdb27d7434c380f0aa4c500e220aa1a9d068514b1ff4d5019e624e7ba1efe82b340a59";
  private static CaviumKeyStoreProvider ksp;
  private static byte[] data = {1, 2, 3};

  @BeforeAll
  public static void createProvider() {
    ksp = mock(CaviumKeyStoreProvider.class);
  }

  @Test
  public void success()
      throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
    final BigInteger publicKey = Numeric.toBigInt(key);
    final ECPublicKey ecPublicKey = EthPublicKeyUtils.createPublicKey(publicKey);
    KeyStore keystore = mock(KeyStore.class);
    when(keystore.getKey(any(), any())).thenReturn(ecPublicKey);
    when(ksp.getKeyStore()).thenReturn(keystore);
    final Signer signer = (new CaviumKeyStoreSignerFactory(ksp)).createSigner("0x");
    assertThat(signer).isNotNull();
    assertThat(signer.getPublicKey()).isNotNull();
  }

  @Test
  public void failure() {
    assertThrows(
        RuntimeException.class,
        () -> {
          final Signer signer = (new CaviumKeyStoreSignerFactory(ksp)).createSigner("0x");
          signer.sign(data);
        });
  }
}
