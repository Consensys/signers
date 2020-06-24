/*
 * Copyright 2019 ConsenSys AG.
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStoreException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class HSMKeyStoreProviderTest {

  private static String library;
  private static String slot;
  private static String pin;

  private static HSMKeyStoreProvider ksp;

  @BeforeAll
  public static void beforeAll() {
    Properties p = new Properties();
    InputStream is = ClassLoader.getSystemResourceAsStream("softhsm.properties");
    try {
      p.load(is);
      library = p.getProperty("library");
      slot = p.getProperty("slot");
      pin = p.getProperty("pin");
    } catch (IOException e) {
      fail("Properties file not found");
    }

    org.junit.jupiter.api.Assumptions.assumeTrue((new File(library).exists()));
    ksp = new HSMKeyStoreProvider(library, slot, pin);
  }

  @AfterAll
  public static void afterAll() {
    if (ksp != null) {
      ksp.shutdown();
    }
  }

  @Test
  void getAllTest() {
    ksp.initialize();
    Enumeration<String> addresses;
    try {
      addresses = ksp.keyStore.aliases();
    } catch (KeyStoreException e) {
      return;
    }
    assertThat(addresses).isNotNull();
    for (String a : Collections.list(addresses)) {
      System.out.println("Listed: " + a);
    }
  }
}
