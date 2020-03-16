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
package tech.pegasys.signers.hashicorp.dsl;

// This assumes there is a Vault Server running at the vault URL (for AT, typically in a docker)
public class HashicorpVaultCommands {

  private final String vaultUrl;

  public HashicorpVaultCommands(final String vaultUrl) {
    this.vaultUrl = vaultUrl;
  }

  public String[] statusCommand() {
    return new String[] {"vault", "status", "-address=" + vaultUrl};
  }

  public String[] initCommand() {
    return new String[] {
      "vault",
      "operator",
      "init",
      "-key-shares=1",
      "-key-threshold=1",
      "-format=json",
      "-address=" + vaultUrl
    };
  }

  public String[] enableSecretEngineCommand(final String vaultRootPath) {
    return new String[] {
      "vault", "secrets", "enable", "-address=" + vaultUrl, "-path=" + vaultRootPath, "kv-v2",
    };
  }

  public String[] unseal(final String unsealKey) {
    return new String[] {
      "vault", "operator", "unseal", "-address=" + vaultUrl, "-format=json", unsealKey
    };
  }

  public String[] putSecretCommand(final String key, final String value, final String path) {
    final String paramString = String.format("%s=%s", key, value);
    return new String[] {
      "vault", "kv", "put", "-address=" + vaultUrl, path, paramString,
    };
  }

  public String[] loginCommand(final String rootToken) {
    return new String[] {"vault", "login", "-address=" + vaultUrl, rootToken};
  }
}
