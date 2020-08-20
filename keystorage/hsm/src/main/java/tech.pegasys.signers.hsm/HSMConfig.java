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
package tech.pegasys.signers.hsm;

import static com.google.common.base.Preconditions.checkNotNull;

import com.fasterxml.jackson.annotation.JsonCreator;

public class HSMConfig {
  private final String library;
  private final String slot;
  private final String pin;

  @JsonCreator
  public HSMConfig(final String library, final String slot, final String pin) {
    this.library = library;
    this.slot = slot;
    this.pin = pin;
  }

  public HSMConfig() {
    this.library = "";
    this.slot = "";
    this.pin = "";
  }

  public String getLibrary() {
    return library;
  }

  public String getSlot() {
    return slot;
  }

  public String getPin() {
    return pin;
  }

  public static class HSMConfigBuilder {

    private String library;
    private String slot;
    private String pin;

    public HSMConfigBuilder withLibrary(final String library) {
      this.library = library;
      return this;
    }

    public HSMConfigBuilder withSlot(final String slot) {
      this.slot = slot;
      return this;
    }

    public HSMConfigBuilder withPin(final String pin) {
      this.pin = pin;
      return this;
    }

    public HSMConfigBuilder fromEnvironmentVariables() {
      library = System.getenv("PKCS11_HSM_LIB");
      slot = System.getenv("PKCS11_HSM_SLOT");
      pin = System.getenv("PKCS11_HSM_PIN");
      return this;
    }

    public HSMConfig build() {
      checkNotNull(library, "PKCS11 library was not set.");
      checkNotNull(slot, "PKCS11 slot was not set.");
      checkNotNull(pin, "PKCS11 pin was not set.");
      return new HSMConfig(library, slot, pin);
    }
  }
}
