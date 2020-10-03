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

import java.nio.file.Path;
import java.util.Objects;

import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

public class FileSizeHandler extends AbstractHandler<Long> {
  private final Path path;

  public FileSizeHandler(final Path path) {
    super("File Size");
    this.path = path;
  }

  @Override
  protected Long processJsonResponse(final JsonObject json, final MultiMap headers) {
    final JsonArray inodesArray = json.getJsonObject("response").getJsonArray("inodes");
    final String fileName = path.getFileName().toString();

    for (int i = 0; i < inodesArray.size(); i++) {
      final JsonObject inodeObject = inodesArray.getJsonObject(i);
      if (Objects.equals(inodeObject.getString("name"), fileName)) {
        return inodeObject.getLong("size");
      }
    }
    return -1L;
  }

  public String body() {
    return new JsonObject().put("path", path.getParent().toString()).put("sha256", true).encode();
  }
}
