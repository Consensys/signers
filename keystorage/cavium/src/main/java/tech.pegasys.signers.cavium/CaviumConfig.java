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

import static com.google.common.base.Preconditions.checkNotNull;

import com.fasterxml.jackson.annotation.JsonCreator;

public class CaviumConfig {
  private final String library;
  private final String pin;

  @JsonCreator
  public CaviumConfig(final String library, final String pin) {
    this.library = library;
    this.pin = pin;
  }

  public CaviumConfig() {
    this.library = "";
    this.pin = "";
  }

  public String getLibrary() {
    return library;
  }

  public String getPin() {
    return pin;
  }

  public static class CaviumConfigBuilder {

    private String library;
    private String pin;

    public CaviumConfigBuilder withLibrary(final String library) {
      this.library = library;
      return this;
    }

    public CaviumConfigBuilder withPin(final String pin) {
      this.pin = pin;
      return this;
    }

    public CaviumConfigBuilder fromEnvironmentVariables() {
      library = System.getenv("AWS_HSM_LIB");
      pin = System.getenv("AWS_HSM_PIN");
      return this;
    }

    public CaviumConfig build() {
      checkNotNull(library, "AWS Cloud HSM library was not set.");
      checkNotNull(pin, "AWS Cloud HSM pin was not set.");
      return new CaviumConfig(library, pin);
    }
  }
}
