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
package tech.pegasys.signers.secp256k1.multikey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.filter;

import tech.pegasys.signers.secp256k1.common.StubbedPublicKey;

import java.io.IOException;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

class PublicKeyFileSelectorTest {

  @Test
  void acceptsSimplePubKeyPathWithTomlExtension() throws IOException {
    final PublicKeyFileSelector fileSelector = new PublicKeyFileSelector();

    final StubbedPublicKey publicKey = new StubbedPublicKey("A".repeat(40));

    final Filter<Path> filter = fileSelector.getSpecificConfigFileFilter(publicKey);

    assertThat(filter.accept(Path.of("B".repeat(40)))).isFalse();
  }
}
