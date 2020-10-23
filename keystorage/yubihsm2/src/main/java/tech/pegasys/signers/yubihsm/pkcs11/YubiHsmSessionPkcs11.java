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

import static java.nio.charset.StandardCharsets.ISO_8859_1;

import tech.pegasys.signers.yubihsm.OpaqueDataFormat;
import tech.pegasys.signers.yubihsm.YubiHsmException;
import tech.pegasys.signers.yubihsm.YubiHsmSession;

import iaik.pkcs.pkcs11.Module;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class YubiHsmSessionPkcs11 implements YubiHsmSession {
  private static final Logger LOG = LogManager.getLogger();
  private final Configuration configuration;
  private Module module;
  private Session session;

  public YubiHsmSessionPkcs11(final Configuration configuration) {
    this.configuration = configuration;
  }

  public void init() {
    this.module =
        Pkcs11ModuleFactory.initPkcs11Module(
            configuration.getPkcs11ModulePath(), configuration.getPkcs11Conf());
    this.session = Pkcs11SessionFactory.loginSession(module, configuration.getPin());
  }

  @Override
  public Bytes fetchOpaqueData(final short opaqueObjId, final OpaqueDataFormat opaqueDataFormat)
      throws YubiHsmException {
    try {
      initFind(opaqueObjId);

      final byte[] data = findData(opaqueObjId);

      return opaqueDataFormat == OpaqueDataFormat.HEX
          ? Bytes.wrap(data)
          : Bytes.fromHexString(new String(data, ISO_8859_1));

    } finally {
      finalizeFind();
    }
  }

  private byte[] findData(final short opaqueObjId) {
    LOG.trace("Find Objects {}", opaqueObjId);

    try {
      final PKCS11Object[] data = session.findObjects(1);
      if (data == null || data.length == 0) {
        LOG.warn("Opaque data not found {}", opaqueObjId);
        throw new YubiHsmException("Opaque data not found");
      }

      return ((ByteArrayAttribute) data[0].getAttributeTable().get(Attribute.VALUE))
          .getByteArrayValue();
    } catch (final TokenException e) {
      LOG.warn("Unable to find opaque data {}:{}", opaqueObjId, e.getMessage());
      throw new YubiHsmException("Opaque data not found", e);
    }
  }

  private void initFind(final short opaqueObjId) {
    LOG.trace("Find Objects Init");
    try {
      session.findObjectsInit(new ExtendedData(opaqueObjId));
    } catch (final TokenException e) {
      LOG.warn("PKCS11 Find Initialization for {} failed: {}", opaqueObjId, e.getMessage());
      throw new YubiHsmException("Find Initialization failed", e);
    }
  }

  private void finalizeFind() {
    LOG.trace("Find Objects Final");
    try {
      session.findObjectsFinal();
    } catch (final TokenException e) {
      LOG.warn("PKCS11 Find finalize failed {}", e.getMessage());
    }
  }

  @Override
  public void close() {
    if (session != null) {
      logoutSession();
      closeSession();
    }

    if (module != null) {
      finalizeModule();
    }
  }

  private void logoutSession() {
    try {
      LOG.trace("Logout Session");
      session.logout();
    } catch (TokenException e) {
      LOG.warn("Unable to logout from session {}", e.getMessage());
    }
  }

  private void closeSession() {
    try {
      LOG.trace("Close session");
      session.closeSession();
    } catch (TokenException e) {
      LOG.warn("Unable to close session {}", e.getMessage());
    }
  }

  private void finalizeModule() {
    try {
      LOG.trace("Finalize module");
      module.finalize(null);
    } catch (TokenException e) {
      LOG.warn("Unable to finalize PKCS11 module {}", e.getMessage());
    }
  }
}
