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

import com.google.common.io.Files;

public class AddressPostFixFilter implements DirectoryStream.Filter<Path> {

  private static final String FILE_EXTENSION = "toml";
  private final String addressToMatch;

  public AddressPostFixFilter(final String addressToMatch) {
    this.addressToMatch = addressToMatch;
  }

  @Override
  public boolean accept(final Path entry) throws IOException {
    return Files.getNameWithoutExtension(entry.toString()).equals(addressToMatch)
        && hasExpectedFileExtension(entry);
  }

  private boolean hasExpectedFileExtension(final Path entry) {
    return Files.getFileExtension(entry.toString()).equals(FILE_EXTENSION);
  }
}
