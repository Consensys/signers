/*
 * Copyright 2022 ConsenSys AG.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SecretsMaps {
  static final String SECRET_NAME_PREFIX_A = "signers-aws-integration/a/";
  static final String SECRET_NAME_PREFIX_B = "signers-aws-integration/b/";

  private final Map<String, SecretValue> prefixASecretsMap;
  private final Map<String, SecretValue> prefixBSecretsMap;
  private final Map<String, SecretValue> allSecretsMap;

  public SecretsMaps() {
    final Map<String, SecretValue> secretMapA = new HashMap<>();
    final Map<String, SecretValue> secretMapB = new HashMap<>();
    final Map<String, SecretValue> allSecretsMap = new HashMap<>();

    for (int i = 1; i <= 4; i++) {
      final SecretValue secretValue = computeSecretValue(i);
      secretMapA.put(computeMapAKey(i), secretValue);
      secretMapB.put(computeMapBKey(i), secretValue);
    }
    allSecretsMap.putAll(secretMapA);
    allSecretsMap.putAll(secretMapB);

    this.prefixASecretsMap = Collections.unmodifiableMap(secretMapA);
    this.prefixBSecretsMap = Collections.unmodifiableMap(secretMapB);
    this.allSecretsMap = Collections.unmodifiableMap(allSecretsMap);
  }

  public Map<String, SecretValue> getPrefixASecretsMap() {
    return prefixASecretsMap;
  }

  public Map<String, SecretValue> getPrefixBSecretsMap() {
    return prefixBSecretsMap;
  }

  public Map<String, SecretValue> getAllSecretsMap() {
    return allSecretsMap;
  }

  public static String computeMapAKey(final int i) {
    return String.format("%ssecret%d", SECRET_NAME_PREFIX_A, i);
  }

  public static String computeMapBKey(final int i) {
    return String.format("%ssecret%d", SECRET_NAME_PREFIX_B, i);
  }

  public static SecretValue computeSecretValue(final int i) {
    final String value = String.format("secret-value%d", i);
    final SecretValue secretValue;
    // due to past test values setup ...
    switch (i) {
      case 1:
        secretValue = new SecretValue(value, "tagKey1", "tagValA");
        break;
      case 2:
        secretValue = new SecretValue(value, "tagKey1", "tagValB");
        break;
      case 3:
        secretValue = new SecretValue(value, "tagKey2", "tagValC");
        break;
      default:
        secretValue = new SecretValue(value, "tagKey2", "tagValB");
        break;
    }
    return secretValue;
  }
}
