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
package tech.pegasys.signers.cavium;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Stream;

import com.google.common.base.Splitter;

public class CaviumKeyStoreProvider extends HSMKeyStoreProvider {

  public CaviumKeyStoreProvider(final CaviumConfig config) {
    library = config.getLibrary();
    if (library.isEmpty()) {
      library = System.getenv("AWS_HSM_LIBRARY");
    }
    slotPin = config.getPin();
    if (slotPin.isEmpty()) {
      slotPin = System.getenv("AWS_HSM_PIN");
    }
    if (slotPin != null && slotPin.contains(":")) {
      List<String> s = Splitter.on(':').splitToList(slotPin);
      setEnv("HSM_PARTITION", "PARTITION_1");
      setEnv("HSM_USER", s.get(0));
      setEnv("HSM_PASSWORD", s.get(1));
    }
  }

  @Override
  protected void initialize() throws HSMKeyStoreInitializationException {
    try {
      provider = new com.cavium.provider.CaviumProvider();
      Security.addProvider(provider);
      keyStore = KeyStore.getInstance("CloudHSM");
    } catch (Exception ex) {
      LOG.debug(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE, ex);
    }
    try {
      keyStore.load(null, slotPin.toCharArray());
    } catch (IOException | NoSuchAlgorithmException | CertificateException ex) {
      LOG.debug(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE, ex);
    }
    LOG.debug("Successfully initialized hsm slot");
  }

  @SuppressWarnings("unchecked")
  private <K, V> void setEnv(final String key, final String value) {
    try {
      final Class<?> processEnvironmentClass = Class.forName("java.lang.ProcessEnvironment");
      final Field theEnvironmentField = processEnvironmentClass.getDeclaredField("theEnvironment");
      final boolean environmentAccessibility = theEnvironmentField.isAccessible();
      theEnvironmentField.setAccessible(true);
      final Map<K, V> env = (Map<K, V>) theEnvironmentField.get(null);
      String OS = System.getProperty("os.name", "unknown").toLowerCase(Locale.ROOT);
      if (OS.contains("win")) {
        if (value == null) {
          env.remove(key);
        } else {
          env.put((K) key, (V) value);
        }
      } else {
        final Class<K> variableClass =
            (Class<K>) Class.forName("java.lang.ProcessEnvironment$Variable");
        final Method convertToVariable = variableClass.getMethod("valueOf", String.class);
        final boolean conversionVariableAccessibility = convertToVariable.isAccessible();
        convertToVariable.setAccessible(true);
        final Class<V> valueClass = (Class<V>) Class.forName("java.lang.ProcessEnvironment$Value");
        final Method convertToValue = valueClass.getMethod("valueOf", String.class);
        final boolean conversionValueAccessibility = convertToValue.isAccessible();
        convertToValue.setAccessible(true);
        if (value == null) {
          env.remove(convertToVariable.invoke(null, key));
        } else {
          env.put((K) convertToVariable.invoke(null, key), (V) convertToValue.invoke(null, value));
          convertToValue.setAccessible(conversionValueAccessibility);
          convertToVariable.setAccessible(conversionVariableAccessibility);
        }
      }
      theEnvironmentField.setAccessible(environmentAccessibility);
      final Field theCaseInsensitiveEnvironmentField =
          processEnvironmentClass.getDeclaredField("theCaseInsensitiveEnvironment");
      final boolean insensitiveAccessibility = theCaseInsensitiveEnvironmentField.isAccessible();
      theCaseInsensitiveEnvironmentField.setAccessible(true);
      final Map<String, String> cienv =
          (Map<String, String>) theCaseInsensitiveEnvironmentField.get(null);
      if (value == null) {
        cienv.remove(key);
      } else {
        cienv.put(key, value);
      }
      theCaseInsensitiveEnvironmentField.setAccessible(insensitiveAccessibility);
    } catch (final ClassNotFoundException
        | NoSuchMethodException
        | IllegalAccessException
        | InvocationTargetException e) {
      throw new IllegalStateException(
          "Failed setting environment variable <" + key + "> to <" + value + ">", e);
    } catch (final NoSuchFieldException e) {
      final Map<String, String> env = System.getenv();
      Stream.of(Collections.class.getDeclaredClasses())
          .filter(c1 -> "java.util.Collections$UnmodifiableMap".equals(c1.getName()))
          .map(
              c1 -> {
                try {
                  return c1.getDeclaredField("m");
                } catch (final NoSuchFieldException e1) {
                  throw new IllegalStateException(
                      "Failed setting environment variable <"
                          + key
                          + "> to <"
                          + value
                          + "> when locating in-class memory map of environment",
                      e1);
                }
              })
          .forEach(
              field -> {
                try {
                  final boolean fieldAccessibility = field.isAccessible();
                  field.setAccessible(true);
                  final Map<String, String> map = (Map<String, String>) field.get(env);
                  if (value == null) {
                    map.remove(key);
                  } else {
                    map.put(key, value);
                  }
                  field.setAccessible(fieldAccessibility);
                } catch (final ConcurrentModificationException e1) {
                  LOG.debug(
                      "Attempted to modify source map: "
                          + field.getDeclaringClass()
                          + "#"
                          + field.getName(),
                      e1);
                } catch (final IllegalAccessException e1) {
                  throw new IllegalStateException(
                      "Failed setting environment variable <"
                          + key
                          + "> to <"
                          + value
                          + ">. Unable to access field!",
                      e1);
                }
              });
    }
    LOG.debug(
        "Set environment variable <"
            + key
            + "> to <"
            + value
            + ">. Sanity Check: "
            + System.getenv(key));
  }
}
