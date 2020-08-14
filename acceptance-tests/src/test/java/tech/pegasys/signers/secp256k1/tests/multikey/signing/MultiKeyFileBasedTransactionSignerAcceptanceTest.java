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

import static java.nio.charset.StandardCharsets.UTF_8;
import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createFileBasedTomlFileAt;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.common.io.Resources;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class MultiKeyFileBasedTransactionSignerAcceptanceTest
    extends MultiKeyTransactionSigningAcceptanceTestBase {

  static final String FILENAME =
      "09b02f8a5fddd222ade4ea4528faefc399623af3f736be3c44f03e2df22fb792f3931a4d9573d333ca74343305762a753388c3422a86d98b713fc91c1ea04842";

  @Test
  public void fileBasedMultiKeyCanSign(@TempDir Path tomlDirectory)
      throws URISyntaxException, IOException {
    final String keyPath =
        new File(Resources.getResource("secp256k1/rich_benefactor_one.json").toURI())
            .getAbsolutePath();

    final Path passwordPath = tomlDirectory.resolve("password");
    Files.write(passwordPath, "pass".getBytes(UTF_8));

    createFileBasedTomlFileAt(
        tomlDirectory.resolve(FILENAME + ".toml"), keyPath, passwordPath.toString());

    setup(tomlDirectory, Path.of(""));
    verifySignature();
  }
}
