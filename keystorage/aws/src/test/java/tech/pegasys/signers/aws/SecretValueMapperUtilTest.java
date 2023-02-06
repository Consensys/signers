/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.signers.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.pegasys.signers.aws.SecretValueMapperUtil.mapSecretValue;

import java.util.Set;

import org.junit.jupiter.api.Test;

class SecretValueMapperUtilTest {

  @Test
  void singleValueIsMapped() {
    Set<String> mappedValues = mapSecretValue((k, v) -> v, "key", "value");
    assertThat(mappedValues).containsOnly("value");
  }

  @Test
  void newlinesValuesAreMapped() {
    Set<String> mappedValues = mapSecretValue((k, v) -> v, "key", "value1\nvalue2");
    assertThat(mappedValues).containsOnly("value1", "value2");

    Set<String> mappedValues2 = mapSecretValue((k, v) -> v, "key", "value1\nvalue2\n");
    assertThat(mappedValues2).containsOnly("value1", "value2");
  }

  @Test
  void emptyStringResultsEmptyCollection() {
    Set<String> mappedValues = mapSecretValue((k, v) -> v, "key", "");
    assertThat(mappedValues).isEmpty();
  }

  @Test
  void emptyLineTerminationsReturnsEmptyStrings() {
    assertThat(mapSecretValue((k, v) -> v, "key", "\n")).containsOnly("");
    assertThat(mapSecretValue((k, v) -> v, "key", "\nok\n\n")).containsOnly("", "ok");
  }

  @Test
  void nullMappedIsNotReturned() {
    Set<String> mappedValues =
        mapSecretValue(
            (k, v) -> {
              if (v.startsWith("err")) {
                return null;
              }
              return v;
            },
            "key",
            "ok1\nerr1\nerr2\nok2");

    assertThat(mappedValues).containsOnly("ok1", "ok2");
  }

  @Test
  void sameValuesAreMappedOnce() {
    Set<String> mappedValues =
        mapSecretValue(
            (k, v) -> {
              if (v.startsWith("err")) {
                return null;
              }
              return v;
            },
            "key",
            "ok\nerr1\nerr2\nok\nok1");

    assertThat(mappedValues).containsOnly("ok", "ok1");
  }
}
