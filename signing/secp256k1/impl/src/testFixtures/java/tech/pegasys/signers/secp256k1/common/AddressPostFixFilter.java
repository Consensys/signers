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
package tech.pegasys.signers.secp256k1.common;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Path;
import java.util.List;

import com.google.common.base.Splitter;

public class AddressPostFixFilter implements DirectoryStream.Filter<Path> {

  private static final String fileExtension = "toml";
  private final String addressToMatch;

  public AddressPostFixFilter(final String addressToMatch) {
    this.addressToMatch = addressToMatch;
  }

  @Override
  public boolean accept(final Path entry) throws IOException {

    final List<String> tokens =
        Splitter.onPattern("\\.(?=[^\\.]+$)").splitToList(entry.getFileName().toString());

    if (tokens.size() < 2) {
      return false;
    }

    return tokens.get(0).toLowerCase().equals(addressToMatch.toLowerCase())
        && hasExpectedFileExtension(entry);
  }

  private boolean hasExpectedFileExtension(final Path entry) {
    return entry.getFileName().toString().toLowerCase().endsWith(fileExtension.toLowerCase());
  }
}
