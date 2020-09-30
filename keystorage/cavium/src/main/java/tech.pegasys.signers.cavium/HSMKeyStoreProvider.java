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

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.concurrent.TimeUnit;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.TokenException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HSMKeyStoreProvider {

  protected static final Logger LOG = LogManager.getLogger();
  private static final String ERROR_CREATING_TMP_FILE_MESSAGE =
      "Failed to create a temp config file";
  protected static final String ERROR_INITIALIZING_PKCS11_KEYSTORE_MESSAGE =
      "Failed to initialize key store";
  protected static final String ERROR_ACCESSING_PKCS11_KEYSTORE_MESSAGE =
      "Failed to access key store";

  protected Provider provider;
  protected KeyStore keyStore;
  protected String library;
  private String configName;
  protected String slotIndex;
  protected String slotPin;
  private Cache<String, Key> cache =
      CacheBuilder.newBuilder().maximumSize(10).expireAfterWrite(10, TimeUnit.MINUTES).build();

  public HSMKeyStoreProvider() {}

  public HSMKeyStoreProvider(final String library, final String slot, final String pin) {
    final StringBuilder sb = new StringBuilder();
    sb.append(String.format("name = %s\n", "HSM"));
    sb.append(String.format("library = %s\n", library));
    sb.append(String.format("slot = %s\n", slot));
    sb.append("attributes(generate, *, *) = { CKA_TOKEN = true }\n");
    sb.append("attributes(generate, CKO_CERTIFICATE, *) = { CKA_PRIVATE=false }\n");
    sb.append("attributes(generate, CKO_PUBLIC_KEY, *) = { CKA_PRIVATE=false }\n");
    final String configContent = sb.toString();
    try {
      Path configPath = Files.createTempFile("pkcs11-", ".cfg");
      File configFile = configPath.toFile();
      configName = configFile.getAbsolutePath();
      // configFile.deleteOnExit();
      Files.write(configPath, configContent.getBytes(Charset.defaultCharset()));
    } catch (IOException ex) {
      LOG.debug(ERROR_CREATING_TMP_FILE_MESSAGE);
      LOG.trace(ex);
      throw new HSMKeyStoreInitializationException(ERROR_CREATING_TMP_FILE_MESSAGE, ex);
    }
    this.library = library;
    slotIndex = slot;
    slotPin = pin;
  }

  public void initialize() throws HSMKeyStoreInitializationException {
    Provider prototype = Security.getProvider("SunPKCS11");
    try {
      provider = prototype.configure(configName);
      keyStore = KeyStore.getInstance("PKCS11", provider);
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
    LOG.debug("Successfully initialized hsm key store");
  }

  public void shutdown() {
    if (library != null)
      try {
        Module pkcs11Module = Module.getInstance(library);
        pkcs11Module.initialize(null);
        pkcs11Module.finalize(null);
      } catch (TokenException | IOException ex) {
        LOG.trace(ex);
      }
  }

  public KeyStore getKeyStore() throws HSMKeyStoreInitializationException {
    if (keyStore == null) initialize();
    return keyStore;
  }

  public Provider getProvider() throws HSMKeyStoreInitializationException {
    if (provider == null) initialize();
    return provider;
  }

  public String getSlotIndex() {
    return slotIndex;
  }

  public Key getKey(String alias) {
    return cache.getIfPresent(alias);
  }

  public void addKey(String alias, Key privateKey) {
    cache.put(alias, privateKey);
  }
}
