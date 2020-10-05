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

import io.vertx.core.MultiMap;
import io.vertx.core.json.JsonObject;

public class FileDownloadIdHandler extends AbstractHandler<String> {
  public FileDownloadIdHandler() {
    super("Download File Id");
  }

  @Override
  protected String processJsonResponse(final JsonObject json, final MultiMap headers) {
    return json.getString("response");
  }
}
