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
package tech.pegasys.signers.interlock;

import tech.pegasys.signers.interlock.model.ApiAuth;
import tech.pegasys.signers.interlock.model.DecryptCredentials;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Defines operations to communicate with f-secure Interlock rest API. See
 * https://www.f-secure.com/en/consulting/foundry/usb-armory.
 *
 * <p>The call sequence should be login, fetchKey, logout. The login operation is time extensive
 * (takes about 4-5 seconds), hence multiple keys should be fetched with single login operation. The
 * logout must be performed as Interlock forces single login session.
 */
public interface InterlockClient {
  /**
   * Performs login to Interlock. This should be the first call.
   *
   * @param volume The LUKS volume name to use.
   * @param password The LUKS volume password
   * @return ApiAuth containing XSRF Token and list of Cookies that will be used by consecutive
   *     calls.
   * @throws InterlockClientException In case login fails.
   */
  ApiAuth login(final String volume, final String password) throws InterlockClientException;

  /**
   * Attempts to fetch contents from file. If decryptCredentials is present, decrypts file, fetch
   * content and finally deletes decrypted file.
   *
   * @param apiAuth An instance of ApiAuth from login call
   * @param path The path of file, for instance "/bls/key1.txt.pgp" or "/bls/key1.txt.aes256ofb"
   * @param decryptCredentials For encrypted file, specify decrypt credentials describing cipher to
   *     use and its password or private key path. For non-encrypted file specify Optional.empty
   * @return contents from file defined by path.
   * @throws InterlockClientException In case of an error while fetching key
   */
  String fetchKey(
      final ApiAuth apiAuth, final Path path, final Optional<DecryptCredentials> decryptCredentials)
      throws InterlockClientException;

  /**
   * Performs logout from Interlock server. This should be the last call sequence.
   *
   * @param apiAuth An instance of ApiAuth returned from login method
   * @throws InterlockClientException If logout fails.
   */
  void logout(final ApiAuth apiAuth) throws InterlockClientException;
}
