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
import tech.pegasys.signers.yubihsm.YubiHsm;
import tech.pegasys.signers.yubihsm.YubiHsmException;

import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Attribute;
import iaik.pkcs.pkcs11.objects.ByteArrayAttribute;
import iaik.pkcs.pkcs11.objects.PKCS11Object;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class Pkcs11YubiHsm implements YubiHsm {
  private static final Logger LOG = LogManager.getLogger();

  private final Pkcs11Session session;

  public Pkcs11YubiHsm(final Pkcs11Session pkcs11Session) {
    this.session = pkcs11Session;
  }

  @Override
  public Bytes fetchOpaqueData(final short opaqueObjId, final OpaqueDataFormat opaqueDataFormat)
      throws YubiHsmException {
    try {
      initFind(opaqueObjId);

      final byte[] data = findData();

      return opaqueDataFormat == OpaqueDataFormat.HEX
          ? Bytes.wrap(data)
          : Bytes.fromHexString(new String(data, ISO_8859_1));

    } finally {
      finalizeFind();
    }
  }

  private void initFind(final short opaqueObjId) {
    LOG.trace("Find Objects Init {}", opaqueObjId);
    try {
      session.getSession().findObjectsInit(new ExtendedData(opaqueObjId));
    } catch (final TokenException e) {
      LOG.warn("PKCS11 Find Initialization for {} failed: {}", opaqueObjId, e.getMessage());
      throw new YubiHsmException("Find Initialization failed", e);
    }
  }

  private byte[] findData() {
    try {
      final PKCS11Object[] data = session.getSession().findObjects(1);
      if (data == null || data.length == 0) {
        throw new YubiHsmException("Opaque data not found");
      }

      return ((ByteArrayAttribute) data[0].getAttributeTable().get(Attribute.VALUE))
          .getByteArrayValue();
    } catch (final TokenException e) {
      throw new YubiHsmException("Opaque data not found", e);
    }
  }

  private void finalizeFind() {
    LOG.trace("Find Objects Final");
    try {
      session.getSession().findObjectsFinal();
    } catch (final TokenException e) {
      LOG.warn("PKCS11 Find finalize failed {}", e.getMessage());
    }
  }
}
