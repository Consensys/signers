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
package tech.pegasys.signers.secp256k1.hsm;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import tech.pegasys.signers.secp256k1.api.TransactionSigner;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class HSMTransactionSignerFactoryTest {

  private static String library;
  private static String slot;
  private static String pin;
  private static String address;

  private static HSMTransactionSignerFactory factory;

  @BeforeAll
  public static void beforeAll() {
    Properties p = new Properties();
    InputStream is =
        ClassLoader.getSystemResourceAsStream("hsm-configs/softhsm-wallet-002.properties");
    try {
      p.load(is);
      library = p.getProperty("library");
      slot = p.getProperty("slot");
      pin = p.getProperty("pin");
    } catch (IOException e) {
      fail("Properties file not found");
    }

    org.junit.jupiter.api.Assumptions.assumeTrue((new File(library)).exists());
    factory = new HSMTransactionSignerFactory(library, slot, pin);
    factory.initialize();
    address = factory.getWallet().generate();
  }

  @AfterAll
  public static void afterAll() {
    if (factory != null) {
      factory.shutdown();
    }
  }

  @Test
  public void success() {
    final TransactionSigner signer = factory.createSigner(address);
    assertThat(signer).isNotNull();
    assertThat(signer.getAddress()).isNotEmpty();
    assertThat(signer.getAddress()).isEqualTo(address);
  }
}
