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
package tech.pegasys.signers.yubihsm.util;

import java.util.Arrays;

public class PaddingUtils {
  private static final byte PADDING_FIRST_BYTE = (byte) 0x80;

  /**
   * Adds the necessary number of bytes so that `ba`'s length will be a multiple of the specified
   * block size. The first of these extra bytes will be 0x80 and the rest are 0x00
   *
   * @param ba The unpadded byte array
   * @param blockSize The number that the resulting array length should be a multiple of
   * @return `ba` with padding
   */
  public static byte[] addPadding(final byte[] ba, final int blockSize) {
    int padLength = blockSize - (ba.length % blockSize);
    byte[] ret = Arrays.copyOf(ba, ba.length + padLength);
    ret[ba.length] = PADDING_FIRST_BYTE;
    return ret;
  }

  /**
   * Removes the padding that was added to make `ba`'s length a multiple of the specified block size
   *
   * @param ba The padded array
   * @param blockSize The number that the resulting array length should be a multiple of
   * @return `ba` without the padding
   */
  public static byte[] removePadding(final byte[] ba, final int blockSize) {
    if (ba.length % blockSize != 0) {
      // Byte array was not padded. Doing nothing
      return ba;
    }
    int index = ba.length - 1;
    while (ba[index] == 0) {
      index--;
    }
    if (ba[index] != PADDING_FIRST_BYTE) {
      // input has no padding
      return ba;
    }

    return Arrays.copyOf(ba, index);
  }
}
