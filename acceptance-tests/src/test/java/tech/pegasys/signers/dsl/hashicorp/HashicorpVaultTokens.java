/*
 * Copyright (C) 2019 ConsenSys AG.
 *
 * The source code is provided to licensees of PegaSys Plus for their convenience and internal
 * business use. These files may not be copied, translated, and/or distributed without the express
 * written permission of an authorized signatory for ConsenSys AG.
 */
package tech.pegasys.signers.dsl.hashicorp;

public class HashicorpVaultTokens {
  private final String unsealKey;
  private final String rootToken;

  public HashicorpVaultTokens(final String unsealKey, final String rootToken) {
    this.unsealKey = unsealKey;
    this.rootToken = rootToken;
  }

  public String getUnsealKey() {
    return unsealKey;
  }

  public String getRootToken() {
    return rootToken;
  }
}
