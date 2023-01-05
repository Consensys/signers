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
package tech.pegasys.signers.fortanixdsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.util.AbstractMap.SimpleEntry;
import java.util.Collection;
import java.util.Optional;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class FortanixDsmTest {
  private static final String SERVER = System.getenv("DSM_SERVER");
  private static final String API_KEY = System.getenv("API_KEY");
  private static final String KEY_ID = System.getenv("KEY_ID");
  private static final Bytes EXPECTED_KEY =
      Bytes.fromHexString("5ec00b6842e0021be1dbacb18b8e5c834cb41fbbf8f7857ee43f1c1ccbe63c4f");
  private static final String EXPECTED_NAME = "hex_bls";

  @BeforeAll
  public static void setup() {
    Assumptions.assumeTrue(SERVER != null, "Set DSM_SERVER environment variable");
    Assumptions.assumeTrue(API_KEY != null, "Set API_KEY environment variable");
    Assumptions.assumeTrue(KEY_ID != null, "Set KEY_ID environment variable");
  }

  @Test
  void fetchExistingSecretValueFromFortanixDsm() {
    final FortanixDSM fortanixDsm = FortanixDSM.createWithApiKeyCredential(SERVER, API_KEY);
    final Optional<Bytes> secretKey = fortanixDsm.fetchSecret(KEY_ID);
    assertThat(secretKey).isNotEmpty().get().isEqualTo(EXPECTED_KEY);
  }

  @Test
  void fetchExistingSecretNameFromFortanixDsm() {
    final FortanixDSM fortanixDsm = FortanixDSM.createWithApiKeyCredential(SERVER, API_KEY);
    final Optional<String> secretKey = fortanixDsm.fetchName(KEY_ID);
    assertThat(secretKey).isNotEmpty().get().isEqualTo(EXPECTED_NAME);
  }

  @Test
  void fetchNonExistingSecretReturnsEmpty() {
    final FortanixDSM fortanixDsm = FortanixDSM.createWithApiKeyCredential(SERVER, API_KEY);
    final Optional<Bytes> secretKey =
        fortanixDsm.fetchSecret(KEY_ID.substring(0, KEY_ID.length() - 1));
    assertThat(secretKey).isEmpty();
  }

  @Test
  void connectingWithInvalidApiKeyIdThrowsException() {
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(
            () ->
                FortanixDSM.createWithApiKeyCredential(
                    SERVER, API_KEY.substring(0, API_KEY.length() - 1)))
        .withMessageContaining("Authentication failed");
  }

  @Test
  void secretsCanBeMappedUsingCustomMappingFunction() {
    final FortanixDSM fortanixDsm = FortanixDSM.createWithApiKeyCredential(SERVER, API_KEY);

    Collection<SimpleEntry<String, Bytes>> entries =
        fortanixDsm.mapSecret(KEY_ID, SimpleEntry::new);

    final Optional<SimpleEntry<String, Bytes>> BlsEntry =
        entries.stream().filter(e -> e.getKey().equals(EXPECTED_NAME)).findAny();
    assertThat(BlsEntry).isPresent();
    assertThat(BlsEntry.get().getValue()).isEqualTo(EXPECTED_KEY);
  }

  @Test
  void fortanixDsmThrowsAwayObjectsWhichFailMapper() {
    final FortanixDSM fortanixDsm = FortanixDSM.createWithApiKeyCredential(SERVER, API_KEY);

    Collection<SimpleEntry<String, Bytes>> entries =
        fortanixDsm.mapSecret(
            KEY_ID,
            (name, value) -> {
              if (name.equals(EXPECTED_NAME)) {
                throw new RuntimeException("Arbitrary Failure");
              }
              return new SimpleEntry<>(name, value);
            });

    final Optional<SimpleEntry<String, Bytes>> BlsEntry =
        entries.stream().filter(e -> e.getKey().equals(EXPECTED_NAME)).findAny();
    assertThat(BlsEntry).isEmpty();
  }
}
