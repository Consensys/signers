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
package tech.pegasys.signers.secp256k1.cavium;

import static com.google.common.base.Preconditions.checkNotNull;

public class CaviumConfig {
  private final String address;

  public CaviumConfig(final String address) {
    this.address = address;
  }

  public String getAddress() {
    return address;
  }

  public static class CaviumConfigBuilder {
    private String address;

    public CaviumConfigBuilder withAddress(final String keyName) {
      this.address = keyName;
      return this;
    }

    public CaviumConfig build() {
      checkNotNull(address, "Address was not set.");
      return new CaviumConfig(address);
    }
  }
}
