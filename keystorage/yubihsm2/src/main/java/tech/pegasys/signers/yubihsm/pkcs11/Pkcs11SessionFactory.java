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
package tech.pegasys.signers.yubihsm.pkcs11;

import tech.pegasys.signers.yubihsm.YubiHsmException;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

class Pkcs11SessionFactory {
  private static final Logger LOG = LogManager.getLogger();

  public static Session loginSession(final Module module, final char[] pin) {
    final Session session = openReadOnlySession(getToken(module));
    try {
      session.login(Session.UserType.USER, pin);
    } catch (final TokenException e) {
      LOG.error("YubiHSM Login failed {}", e.getMessage());
      throw new YubiHsmException("Login Failed", e);
    }
    return session;
  }

  private static Token getToken(final Module module) {
    final Slot[] slotList;
    try {
      slotList = module.getSlotList(Module.SlotRequirement.TOKEN_PRESENT);
      if (slotList == null || slotList.length == 0) {
        LOG.error("Empty PKCS11 slot list");
        throw new YubiHsmException("Unable to obtain slot");
      }
    } catch (final TokenException e) {
      LOG.error("Unable to obtain PKCS11 slot list {}", e.getMessage());
      throw new YubiHsmException("Unable to obtain slot", e);
    }

    try {
      return slotList[0].getToken();
    } catch (TokenException e) {
      LOG.error("Unable to get PKCS11 Token from first slot {}", e.getMessage());
      throw new YubiHsmException("Unable to get Token from first slot", e);
    }
  }

  private static Session openReadOnlySession(final Token token) {
    try {
      return token.openSession(
          Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
    } catch (final TokenException e) {
      LOG.error("Unable to open PKCS11 session {}", e.getMessage());
      throw new YubiHsmException("Unable to open PKCS11 session", e);
    }
  }
}
