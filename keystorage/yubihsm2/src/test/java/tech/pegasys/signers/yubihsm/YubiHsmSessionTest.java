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
package tech.pegasys.signers.yubihsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

import tech.pegasys.signers.yubihsm.backend.YubiHsmBackend;
import tech.pegasys.signers.yubihsm.backend.YubiHsmBackendTestFactory;
import tech.pegasys.signers.yubihsm.exceptions.YubiHsmException;
import tech.pegasys.signers.yubihsm.model.Opaque;

import java.nio.file.Path;

import io.specto.hoverfly.junit5.HoverflyExtension;
import io.specto.hoverfly.junit5.api.HoverflyConfig;
import io.specto.hoverfly.junit5.api.HoverflySimulate;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;

@Nested
@HoverflySimulate(
    enableAutoCapture = true,
    config =
        @HoverflyConfig(captureAllHeaders = true, proxyLocalHost = true, statefulCapture = true))
@ExtendWith(HoverflyExtension.class)
class YubiHsmSessionTest {

  @Test
  void authenticateSessionAndGetOpaqueData(@TempDir Path tempDir) {
    final YubiHsmBackend backend = YubiHsmBackendTestFactory.createYubiHsmBackend(tempDir);

    try (final YubiHsmSession yubiHsmSession =
        spy(new YubiHsmSession(backend, (short) 1, "password".toCharArray()))) {
      when(yubiHsmSession.getHostChallenge()).thenReturn(Bytes.fromHexString("aaaabbbbccccdddd"));

      yubiHsmSession.authenticateSession();

      final Bytes expected =
          Bytes.fromHexString("0x5e8d5667ce78982a07242739ab03dc63c91e830c80a5b6adca777e3f216a405d");

      final Bytes key1 = new Opaque((short) 15).getOpaque(yubiHsmSession, Opaque.OutputFormat.HEX);
      assertThat(key1).isEqualTo(expected);

      final Bytes key2 =
          new Opaque((short) 16).getOpaque(yubiHsmSession, Opaque.OutputFormat.ASCII);
      assertThat(key2).isEqualTo(expected);
    }
  }
}

@Nested
@HoverflySimulate(
    enableAutoCapture = true,
    config =
        @HoverflyConfig(captureAllHeaders = true, proxyLocalHost = true, statefulCapture = true))
@ExtendWith(HoverflyExtension.class)
class YubiHsmInvalidAuthenticateSessionTest {

  @Test
  void invalidCredentialsThrowsException(@TempDir Path tempDir) {
    final YubiHsmBackend backend = YubiHsmBackendTestFactory.createYubiHsmBackend(tempDir);

    try (final YubiHsmSession session =
        spy(new YubiHsmSession(backend, (short) 1, "invalidpassword".toCharArray()))) {
      when(session.getHostChallenge()).thenReturn(Bytes.fromHexString("aaaabbbbccccdddd"));

      assertThatExceptionOfType(YubiHsmException.class)
          .isThrownBy(session::authenticateSession)
          .withMessage("Wrong Authentication Key");
    }
  }
}

@Nested
@HoverflySimulate(
    enableAutoCapture = true,
    config =
        @HoverflyConfig(captureAllHeaders = true, proxyLocalHost = true, statefulCapture = true))
@ExtendWith(HoverflyExtension.class)
class YubiHsmInvalidOpaqueTest {

  @Test
  void nonExistingOpaqueThrowsError(@TempDir Path tempDir) {
    final YubiHsmBackend backend = YubiHsmBackendTestFactory.createYubiHsmBackend(tempDir);

    try (final YubiHsmSession yubiHsmSession =
        spy(new YubiHsmSession(backend, (short) 1, "password".toCharArray()))) {
      when(yubiHsmSession.getHostChallenge()).thenReturn(Bytes.fromHexString("aaaabbbbccccdddd"));

      yubiHsmSession.authenticateSession();

      final short opaqueId = (short) 400;
      final Opaque opaque = new Opaque(opaqueId);
      assertThatExceptionOfType(YubiHsmException.class)
          .isThrownBy(() -> opaque.getOpaque(yubiHsmSession, Opaque.OutputFormat.HEX))
          .withMessage("No object found matching given ID and Type");
    }
  }
}
