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
import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createCaviumTomlFileAt;

import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class CaviumTomlLoadingAcceptanceTest extends MultiKeyAcceptanceTestBase {

  static final String FILENAME = "199dad4da603c24d55a9562ff680fbdea7ebd797";
  static final String ADDRESS = "0x199DaD4da603C24D55A9562fF680FbDEa7Ebd797";

  @Test
  void caviumSignersAreCreatedAndExpectedAddressIsReported(@TempDir Path tomlDirectory) {
    createCaviumTomlFileAt(tomlDirectory.resolve("arbitrary_prefix" + FILENAME + ".toml"), ADDRESS);

    setup(tomlDirectory);

    assertThat(signerProvider.availableAddresses()).containsOnly("0x" + FILENAME);
  }

  @Test
  void incorrectlyNamedCaviumFileIsNotLoaded(@TempDir Path tomlDirectory) {
    createCaviumTomlFileAt(
        tomlDirectory.resolve("ffffffffffffffffffffffffffffffffffffffff.toml"), ADDRESS);

    setup(tomlDirectory);

    assertThat(signerProvider.availableAddresses()).isEmpty();
  }
}
