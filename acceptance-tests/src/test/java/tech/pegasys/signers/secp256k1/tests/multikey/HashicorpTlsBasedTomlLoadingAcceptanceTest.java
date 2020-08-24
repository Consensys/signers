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
package tech.pegasys.signers.secp256k1.tests.multikey;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createHashicorpTomlFileAt;

import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;
import tech.pegasys.signers.secp256k1.HashicorpSigningParams;

import java.nio.file.Path;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.web3j.utils.Numeric;

class HashicorpTlsBasedTomlLoadingAcceptanceTest extends MultiKeyAcceptanceTestBase {

  public static final String PUBLIC_KEY_HEX_STRING =
      "09b02f8a5fddd222ade4ea4528faefc399623af3f736be3c44f03e2df22fb792f3931a4d9573d333ca74343305762a753388c3422a86d98b713fc91c1ea04842";

  private static HashicorpSigningParams hashicorpNode;

  @BeforeAll
  static void setUpBase() {
    hashicorpNode = HashicorpHelpers.createLoadedHashicorpVault(true);
  }

  @Test
  void hashicorpSignerIsCreatedAndExpectedAddressIsReported(@TempDir final Path tempDir) {
    createHashicorpTomlFileAt(tempDir.resolve(PUBLIC_KEY_HEX_STRING + ".toml"), hashicorpNode);
    setup(tempDir, Path.of(""));
    assertThat(
            signerProvider.availablePublicKeys().stream()
                .map(EthPublicKeyUtils::toByteArray)
                .collect(Collectors.toList()))
        .containsOnly(Numeric.hexStringToByteArray(PUBLIC_KEY_HEX_STRING));
  }

  @AfterAll
  static void tearDown() {
    hashicorpNode.shutdown();
  }
}
