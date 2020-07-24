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

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.List;

import com.google.common.base.Splitter;

class AddressFileMatcher implements DirectoryStream.Filter<Path> {

  private final String addressToMatch;
  final String extension;

  public AddressFileMatcher(final String addressToMatch, final String extension) {
    if (addressToMatch.startsWith("0x")) {
      this.addressToMatch = addressToMatch.replace("0x", "");
    } else {
      this.addressToMatch = addressToMatch;
    }
    this.extension = extension;
  }

  @Override
  public boolean accept(final Path entry) throws IOException {
    final String filename = entry.getFileName().toString();
    final List<String> tokens = Splitter.onPattern("\\.(?=[^\\.]+$)").splitToList(filename);

    if (tokens.size() < 2) {
      return false;
    }

    return tokens.get(0).toLowerCase().endsWith(addressToMatch.toLowerCase())
        && (tokens.get(tokens.size() - 1).equals(extension));
  }
}
