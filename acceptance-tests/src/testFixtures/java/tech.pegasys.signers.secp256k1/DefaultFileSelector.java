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
package tech.pegasys.signers.secp256k1;

import tech.pegasys.signers.secp256k1.api.FileSelector;
import tech.pegasys.signers.secp256k1.api.PublicKey;

import java.nio.file.DirectoryStream.Filter;
import java.nio.file.Path;

public class DefaultFileSelector implements FileSelector<PublicKey> {

  @Override
  public Filter<Path> getAllConfigFilesFilter() {
    return entry -> entry.getFileName().toString().endsWith("toml");
  }

  @Override
  public Filter<Path> getSpecificConfigFileFilter(final PublicKey publicKey) {
    return entry -> {
      final String filename = publicKey.toEthHexString().substring(2); // remove 0x prefix
      return entry.getFileName().toString().equals(filename + ".toml");
    };
  }
}
