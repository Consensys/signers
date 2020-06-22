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
import static org.mockito.Mockito.mock;

import tech.pegasys.signers.cavium.CaviumKeyStoreProvider;
import tech.pegasys.signers.secp256k1.api.TransactionSigner;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class CaviumKeyStoreSignerFactoryTest {

  private static CaviumKeyStoreProvider ksp;

  @BeforeAll
  public static void createProvider() {
    ksp = mock(CaviumKeyStoreProvider.class);
  }

  @Test
  public void success() {
    final TransactionSigner signer = (new CaviumKeyStoreSignerFactory(ksp)).createSigner("0x");

    assertThat(signer).isNotNull();
    assertThat(signer.getAddress()).isNotEmpty();
  }
}
