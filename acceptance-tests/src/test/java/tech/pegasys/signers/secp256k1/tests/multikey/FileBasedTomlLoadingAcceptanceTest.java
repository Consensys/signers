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
import static tech.pegasys.signers.secp256k1.MultiKeyTomlFileUtil.createFileBasedTomlFileAt;

import tech.pegasys.signers.secp256k1.EthPublicKeyUtils;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;

import com.google.common.io.Resources;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileBasedTomlLoadingAcceptanceTest extends MultiKeyAcceptanceTestBase {

  static final String PUBLIC_KEY_HEX_STRING =
      "b0de161ce49581aa75f25852fb1bb882c8921ff5f6eaca9329f5c5f34966085a704f0a555c148359ebaffbe0d92712386890606a5ac8e54563db8279f2120f5d";

  @Test
  void validFileBasedTomlFileProducesSignerWhichReportsMatchingAddress(@TempDir Path tomlDirectory)
      throws URISyntaxException {
    createFileBasedTomlFileAt(
        tomlDirectory.resolve(PUBLIC_KEY_HEX_STRING + ".toml").toAbsolutePath(),
        new File(
                Resources.getResource(
                        "secp256k1/UTC--2019-12-05T05-17-11.151993000Z--a01f618424b0113a9cebdc6cb66ca5b48e9120c5.key")
                    .toURI())
            .getAbsolutePath(),
        new File(
                Resources.getResource(
                        "secp256k1/UTC--2019-12-05T05-17-11.151993000Z--a01f618424b0113a9cebdc6cb66ca5b48e9120c5.password")
                    .toURI())
            .getAbsolutePath());

    setup(tomlDirectory, Path.of(""));

    assertThat(signerProvider.availablePublicKeys().stream().map(EthPublicKeyUtils::toHexString))
        .containsOnly("0x" + PUBLIC_KEY_HEX_STRING);
  }

  @Test
  void validFileBasedTomlFileWithMultineLinePasswordFileProducesSignerWhichReportsMatchingAddress(
      @TempDir Path tomlDirectory) throws URISyntaxException, IOException {
    final Path passwordFile =
        Files.writeString(
            tomlDirectory.resolve("password.txt"), String.format("password%nsecond line%n"));
    createFileBasedTomlFileAt(
        tomlDirectory.resolve(PUBLIC_KEY_HEX_STRING + ".toml").toAbsolutePath(),
        new File(
                Resources.getResource(
                        "secp256k1/UTC--2019-12-05T05-17-11.151993000Z--a01f618424b0113a9cebdc6cb66ca5b48e9120c5.key")
                    .toURI())
            .getAbsolutePath(),
        passwordFile.toString());

    setup(tomlDirectory, Path.of(""));

    assertThat(signerProvider.availablePublicKeys().stream().map(EthPublicKeyUtils::toHexString))
        .containsOnly("0x" + PUBLIC_KEY_HEX_STRING);
  }
}
