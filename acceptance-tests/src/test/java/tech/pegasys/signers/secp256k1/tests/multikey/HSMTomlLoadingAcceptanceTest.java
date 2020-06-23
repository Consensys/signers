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
import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createHSMTomlFileAt;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class HSMTomlLoadingAcceptanceTest extends MultiKeyAcceptanceTestBase {

  static final String FILENAME = "6b56d4db090acb3edc4a334c4773056040e74dcd";
  static final String ADDRESS = "0x6b56D4Db090aCB3eDc4a334C4773056040E74DcD";
  static final String SLOT = "WALLET-001";

  @Test
  void hsmSignersAreCreatedAndExpectedAddressIsReported(@TempDir Path tomlDirectory) {
    createHSMTomlFileAt(
        tomlDirectory.resolve("arbitrary_prefix" + FILENAME + ".toml"), ADDRESS, SLOT);

    setup(tomlDirectory);

    assertThat(signerProvider.availableAddresses()).containsOnly("0x" + FILENAME);
  }

  @Test
  void incorrectlyNamedHSMFileIsNotLoaded(@TempDir Path tomlDirectory) {
    createHSMTomlFileAt(
        tomlDirectory.resolve("ffffffffffffffffffffffffffffffffffffffff.toml"), ADDRESS, SLOT);

    setup(tomlDirectory);

    assertThat(signerProvider.availableAddresses()).isEmpty();
  }
}
