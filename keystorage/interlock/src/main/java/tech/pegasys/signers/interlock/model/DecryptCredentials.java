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
package tech.pegasys.signers.interlock.model;

import java.nio.file.Path;

public class DecryptCredentials {
  private Cipher cipher;
  private String password;
  private Path privateKeyPath;

  /**
   * For Symmetric cipher AES-256-OFB which takes the password.
   *
   * @param cipher AES-256-OFB
   * @param password The password to decrypt the file.
   */
  public DecryptCredentials(final Cipher cipher, final String password) {
    this.cipher = cipher;
    this.password = password;
    this.privateKeyPath = null;
  }

  /**
   * For Asymmetric cipher OpenPGP which takes path to the private key in Interlock.
   *
   * @param cipher OpenPGP
   * @param privateKeyPath The path to private key file, for example /keys/pgp/private/test.armor.
   */
  public DecryptCredentials(final Cipher cipher, final Path privateKeyPath) {
    this.cipher = cipher;
    this.password = "";
    this.privateKeyPath = privateKeyPath;
  }

  public Cipher getCipher() {
    return cipher;
  }

  public String getPassword() {
    return password;
  }

  public Path getPrivateKeyPath() {
    return privateKeyPath;
  }
}
