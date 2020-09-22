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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.apache.commons.io.IOUtils;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;

public class ProcessUtil {
  // visible for testing as well
  static String executeProcess(
      final List<String> args, final Map<String, String> additionalEnvVars, String password)
      throws IOException, TimeoutException, InterruptedException {
    final ProcessResult processResult =
        new ProcessExecutor()
            .environment(additionalEnvVars)
            .command(args)
            .readOutput(true)
            .redirectInput(IOUtils.toInputStream(password + "\n", StandardCharsets.UTF_8.name()))
            .destroyOnExit()
            .execute();

    final List<String> outputLines = processResult.getOutput().getLinesAsUTF8();
    if (processResult.getExitValue() == 0) {
      return outputLines.get(outputLines.size() - 1);
    }

    throw new YubiHsmException(
        "Unable to fetch data from YubiHSM: " + outputLines.get(outputLines.size() - 1));
  }
}
