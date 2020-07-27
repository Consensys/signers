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

import tech.pegasys.signers.secp256k1.api.FileSelector;
import tech.pegasys.signers.secp256k1.api.PublicKey;

import java.io.IOException;
import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;
import java.util.List;

import com.google.common.base.Splitter;

/*
Sample FileSelector which accepts:
* files with an extension of toml (case insensitive)
* first part of filename is the public keys hex string representation (without 0x prefix), case insensitive
* Ignores interim "dotted" elements (eg <publicKey>.arbitrary.data.toml is valid)
 */
public class PublicKeyFileSelector implements FileSelector<PublicKey> {

  final String fileExtension = "toml";

  @Override
  public Filter<Path> getCollectiveFilter() {
    return this::hasExpectedFileExtension;
  }

  @Override
  public Filter<Path> getSpecificConfigFileFilter(final PublicKey selectionCriterion) {
    return entry -> matchesPublicKey(selectionCriterion, entry);
  }

  public boolean matchesPublicKey(final PublicKey publicKey, final Path entry) throws IOException {
    String expectedFilename = publicKey.toString();
    if (expectedFilename.startsWith("0x")) {
      expectedFilename = expectedFilename.substring(2);
    }

    final List<String> tokens =
        Splitter.onPattern("\\.(?=[^\\.]+$)").splitToList(entry.getFileName().toString());

    if (tokens.size() < 2) {
      return false;
    }

    return tokens.get(0).toLowerCase().equals(expectedFilename.toLowerCase())
        && hasExpectedFileExtension(entry);
  }

  private boolean hasExpectedFileExtension(final Path entry) {
    return entry.getFileName().toString().toLowerCase().endsWith(fileExtension.toLowerCase());
  }
}
