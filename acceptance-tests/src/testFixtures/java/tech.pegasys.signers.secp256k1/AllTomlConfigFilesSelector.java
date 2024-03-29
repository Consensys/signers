/*
 * Copyright 2021 ConsenSys AG.
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

import java.nio.file.DirectoryStream;
import java.nio.file.Path;

public class AllTomlConfigFilesSelector implements FileSelector<Void> {
  @Override
  public DirectoryStream.Filter<Path> getConfigFilesFilter(final Void selectionCriteria) {
    return entry -> entry.getFileName().toString().endsWith("toml");
  }
}
