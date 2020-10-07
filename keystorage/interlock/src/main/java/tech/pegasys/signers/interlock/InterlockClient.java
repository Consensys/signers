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

import java.nio.file.Path;

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
   * Fetch key from given path. It is expected that the private key is stored in hex format in given
   * file.
   *
   * @param apiAuth An instance of ApiAuth from login call
   * @param keyPath The path of key file in Interlock, for instance "/bls/key1.txt"
   * @return contents from file defined by path.
   * @throws InterlockClientException In case of an error while fetching key
   */
  String fetchKey(final ApiAuth apiAuth, final Path keyPath) throws InterlockClientException;

  /**
   * Performs logout from Interlock server. This should be the last call sequence.
   *
   * @param apiAuth An instance of ApiAuth returned from login method
   * @throws InterlockClientException If logout fails.
   */
  void logout(final ApiAuth apiAuth) throws InterlockClientException;
}
