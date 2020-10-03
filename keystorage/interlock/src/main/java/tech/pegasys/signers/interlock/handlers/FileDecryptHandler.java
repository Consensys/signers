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
package tech.pegasys.signers.interlock.handlers;

import tech.pegasys.signers.interlock.model.Cipher;
import tech.pegasys.signers.interlock.model.DecryptCredentials;

import java.nio.file.Path;
import java.util.Objects;

import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonObject;
import org.apache.commons.io.FilenameUtils;

public class FileDecryptHandler extends AbstractHandler<Path> {
  private final Path path;
  private final DecryptCredentials decryptCredentials;

  public FileDecryptHandler(final Path path, final DecryptCredentials decryptCredentials) {
    super("File Decrypt");
    this.path = path;
    this.decryptCredentials = decryptCredentials;
  }

  @Override
  protected Path processJsonResponse(final JsonObject json, final MultiMap headers) {
    // Following decrypted file naming is observed in Interlock UI.
    final String fileName = path.getFileName().toString();
    if (Objects.equals(
        FilenameUtils.getExtension(fileName),
        decryptCredentials.getCipher().getCipherExtension())) {
      return path.resolveSibling(FilenameUtils.removeExtension(fileName));
    }

    return path.resolveSibling(fileName + ".decrypted");
  }

  @Override
  public String body() {
    final Cipher cipher = decryptCredentials.getCipher();
    final String password = cipher.isUsePassword() ? decryptCredentials.getPassword() : "";
    final String key =
        cipher.isUsePrivateKey() ? decryptCredentials.getPrivateKeyPath().toString() : "";
    return new JsonObject()
        .put("src", path)
        .put("password", password)
        .put("verify", false)
        .put("key", key)
        .put("sig_key", "")
        .put("cipher", cipher.getCipherName())
        .encode();
  }
}
