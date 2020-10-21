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
package tech.pegasys.signers.yubihsm.model;

import static java.nio.charset.StandardCharsets.UTF_8;

import tech.pegasys.signers.yubihsm.exceptions.YubiHsmException;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.tuweni.bytes.Bytes;

public class AuthenticationKey {

  private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final int KEY_SIZE = 16;
  private static final byte[] SALT = "Yubico".getBytes(UTF_8);
  private static final int ITERATIONS = 10000;

  private final short authKeyId;

  /** The long term encryption key of this Authentication Key */
  private final Bytes encryptionKey;
  /** The long term MAC key of this Authentication Key */
  private final Bytes macKey;

  /**
   * Creates an AuthenticationKey object containing the long term encryption key and MAC key derived
   * from the password
   *
   * @param authKeyId The Object ID of the authentication key
   * @param password The password to derive the long term encryption key and MAC key from
   */
  public AuthenticationKey(final short authKeyId, final char[] password) {
    this.authKeyId = authKeyId;
    final Bytes keyBytes;
    try {
      keyBytes = deriveSecretKey(password);
    } catch (final GeneralSecurityException e) {
      throw new YubiHsmException("Error in deriving secret key", e);
    }
    this.encryptionKey = keyBytes.slice(0, KEY_SIZE).copy();
    this.macKey = keyBytes.slice(KEY_SIZE).copy();
  }

  private Bytes deriveSecretKey(final char[] password)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    if (password.length == 0) {
      throw new IllegalArgumentException("Missing password for derivation of authentication key");
    }

    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
    // keyLength in bits: 2 keys each KEY_SIZE long * 8 bits
    PBEKeySpec keySpec = new PBEKeySpec(password, SALT, ITERATIONS, KEY_SIZE * 2 * 8);
    // in each byte
    SecretKey key = keyFactory.generateSecret(keySpec);
    return Bytes.wrap(key.getEncoded());
  }

  /** @return The long term encryption key of this Authentication Key */
  public Bytes getEncryptionKey() {
    return encryptionKey;
  }

  /** @return The long term MAC key of this Authentication Key */
  public Bytes getMacKey() {
    return macKey;
  }

  public short getAuthKeyId() {
    return authKeyId;
  }
}
