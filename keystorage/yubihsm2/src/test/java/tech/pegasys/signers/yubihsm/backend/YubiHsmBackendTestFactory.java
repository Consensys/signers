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
package tech.pegasys.signers.yubihsm.backend;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;

public class YubiHsmBackendTestFactory {
  public static YubiHsmBackend createYubiHsmBackend(final Path tempDir) {
    final Path knownServersFile = tempDir.resolve("knownServersFile.txt");
    final Optional<Duration> timeout = Optional.of(Duration.ofSeconds(3));
    final YubihsmConnectorBackend backend =
        new YubihsmConnectorBackend(
            URI.create("http://localhost:12345"), timeout, timeout, knownServersFile);
    backend.enableDebugHeader();
    return backend;
  }
}
