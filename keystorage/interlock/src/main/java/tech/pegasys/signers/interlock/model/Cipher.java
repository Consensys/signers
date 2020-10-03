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

public enum Cipher {
  OPENPGP("OpenPGP", ".pgp", false, true),
  AES256OFB("AES-256-OFB", ".aes256ofb", true, false);

  private final String cipherName;
  private final String cipherExtension;
  private final boolean usePassword;
  private final boolean usePrivateKey;

  Cipher(
      final String cipherName,
      final String cipherExtension,
      final boolean usePassword,
      final boolean usePrivateKey) {
    this.cipherName = cipherName;
    this.cipherExtension = cipherExtension;
    this.usePassword = usePassword;
    this.usePrivateKey = usePrivateKey;
  }

  public String getCipherName() {
    return cipherName;
  }

  public String getCipherExtension() {
    return cipherExtension;
  }

  public boolean isUsePassword() {
    return usePassword;
  }

  public boolean isUsePrivateKey() {
    return usePrivateKey;
  }
}
