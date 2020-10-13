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
package tech.pegasys.signers.yubihsm2;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

// a dumb YubiHSM simulator for AT which prints BLS or SECP private key on standard output
public class YubiShellSimulator {
  private static final Map<String, String> argsMap = new HashMap<>();

  public static void main(String[] args) {
    if (args.length == 0) {
      System.err.println("--config-file=<path>");
      System.exit(-1);
    }

    final String[] kv = args[0].split("=");
    if (kv == null || kv.length != 2 || !Objects.equals("--config-file", kv[0])) {
      System.err.println("Argument should be in format --config-file=<path>");
      System.exit(-1);
    }

    final List<String> lines;
    try {
      lines = Files.readAllLines(Path.of(kv[1]), UTF_8);
    } catch (IOException e) {
      System.err.println("Unable to read config file: " + e.getMessage());
      System.exit(-1);
      return;
    }

    for (String arg : lines) {
      final String[] configOptions = arg.split(" ");
      argsMap.put(configOptions[0], configOptions[1]);
    }

    // make sure required arguments are passed
    if (!argsMap.containsKey("connector")) {
      System.err.println("connector is missing");
      System.exit(-1);
    }
    if (!argsMap.containsKey("authkey")) {
      System.err.println("authkey is missing");
      System.exit(-1);
    }
    if (!argsMap.containsKey("object-id")) {
      System.err.println("object-id is missing");
      System.exit(-1);
    }
    if (!argsMap.containsKey("action")) {
      System.err.println("action is missing");
      System.exit(-1);
    }

    if (!"get-opaque".equals(argsMap.get("action"))) {
      System.err.println("action get-opaque is missing");
      System.exit(-1);
    }

    System.out.println("Session keepalive set up to run every 15 seconds");
    System.out.println("Created session 0");

    // if object-id = 1, return BLS key otherwise return SECP key
    final String objId = argsMap.get("object-id");
    if (objId.equals("1")) {
      // BLS
      System.out.println("3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35");
    } else {
      // SECP
      System.out.println("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63");
    }
  }
}
