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
package tech.pegasys.signers.secp256k1.tests.multikey.signing;

import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createHashicorpTomlFileAt;

import tech.pegasys.signers.hashicorp.dsl.DockerClientFactory;
import tech.pegasys.signers.secp256k1.HashicorpSigningParams;
import tech.pegasys.signers.secp256k1.tests.multikey.HashicorpHelpers;

import java.nio.file.Path;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class MultiKeyHashicorpTransactionSignerAcceptanceTest
    extends MultiKeyTransactionSigningAcceptanceTestBase {

  static final String FILENAME = "fe3b557e8fb62b89f4916b721be55ceb828dbd73";

  private static HashicorpSigningParams hashicorpNode;

  @BeforeAll
  static void preSetup() {
    hashicorpNode =
        HashicorpHelpers.createLoadedHashicorpVault(new DockerClientFactory().create(), false);
  }

  @Test
  void hashicorpLoadedFromMultiKeyCanSign(@TempDir Path tomlDirectory) {

    createHashicorpTomlFileAt(tomlDirectory.resolve(FILENAME + ".toml"), hashicorpNode);

    setup(tomlDirectory);
    verifySignature();
  }

  @AfterAll
  static void tearDown() {
    if (hashicorpNode != null) {
      hashicorpNode.shutdown();
      hashicorpNode = null;
    }
  }
}
