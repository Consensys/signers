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
package tech.pegasys.signers.yubihsm;

import tech.pegasys.signers.yubihsm.backend.YubiHsmBackend;
import tech.pegasys.signers.yubihsm.exceptions.YubiHsmException;
import tech.pegasys.signers.yubihsm.model.AuthenticationKey;
import tech.pegasys.signers.yubihsm.model.Command;
import tech.pegasys.signers.yubihsm.model.Errors;
import tech.pegasys.signers.yubihsm.util.CommandUtils;
import tech.pegasys.signers.yubihsm.util.PaddingUtils;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;

/** Adapted from <a href="https://github.com/YubicoLabs/yubihsm-java">YubiHSM Java</a> */
public class YubiHsmSession implements AutoCloseable {
  private static final Logger LOG = LogManager.getLogger();

  public enum SessionStatus {
    NOT_INITIALIZED,
    CREATED,
    AUTHENTICATED,
    CLOSED
  }

  private static final byte KEY_ENC = 0x04;
  private static final byte KEY_MAC = 0x06;
  private static final byte KEY_RMAC = 0x07;
  private static final byte CARD_CRYPTOGRAM = 0x00;
  private static final byte HOST_CRYPTOGRAM = 0x01;

  private static final int PADDING_BLOCK_SIZE = 16;
  private static final int CHALLENGE_SIZE = 16;
  private static final int HALF_CHALLENGE_SIZE = 8;
  private static final int SESSION_KEY_SIZE = 16;
  private static final int MESSAGE_MAC_SIZE = 8;
  private static final int SESSION_COUNTER_SIZE = 16;
  private static final byte MIN_SESSION_ID = 0;
  private static final byte MAX_SESSION_ID = 15;
  private static final int SESSION_ID_SIZE = 1;

  private final YubiHsmBackend backend;
  private final AuthenticationKey authenticationKey;

  private byte sessionID = (byte) -1;
  private SessionStatus status = SessionStatus.NOT_INITIALIZED;
  private byte[] sessionEncKey = null;
  private byte[] sessionMacKey = null;
  private byte[] sessionRMacKey = null;
  private byte[] sessionChain = null;
  private long lowCounter = 0;
  private long highCounter = 0;

  public YubiHsmSession(final YubiHsmBackend backend, final short authKeyId, char[] password) {
    this.backend = backend;
    authenticationKey = new AuthenticationKey(authKeyId, password);
  }

  /** Creates and authenticate a session with the device */
  public void authenticateSession() {
    if (status == SessionStatus.AUTHENTICATED) {
      LOG.debug("Session already authenticated. {}" + sessionID);
    }

    // create session
    final Bytes hostChallenge = Bytes.wrap(new SecureRandom().generateSeed(HALF_CHALLENGE_SIZE));
    LOG.trace("Host Challenge: {}:{}", hostChallenge, hostChallenge.size());
    List<Bytes> deviceChallengeResponse = createSessionAndGetResponse(hostChallenge);

    final Bytes challenge = Bytes.wrap(hostChallenge, deviceChallengeResponse.get(0));
    LOG.trace("Authenticating session context: {}:{}", challenge, challenge.size());

    deriveSessionKeys(challenge);
    verifyDeviceCryptogram(deviceChallengeResponse.get(1), challenge);

    // Derive a host cryptogram
    byte[] hostCryptogram =
        deriveKey(sessionMacKey, HOST_CRYPTOGRAM, challenge.toArrayUnsafe(), HALF_CHALLENGE_SIZE);

    // Authenticate the session
    byte[] authenticateSessionMessage = getAuthenticateSessionMessage(hostCryptogram);
    Bytes authenticateSessionResponse = backend.transceive(Bytes.wrap(authenticateSessionMessage));

    // Parse the response
    authenticateSessionResponse =
        CommandUtils.parseCmdResponse(Command.AUTHENTICATE_SESSION, authenticateSessionResponse);

    CommandUtils.verifyResponseLength(
        Command.AUTHENTICATE_SESSION, authenticateSessionResponse.size(), 0);

    status = SessionStatus.AUTHENTICATED;
    lowCounter = 1;
  }

  /**
   * Sends a command to the device and gets a response over an authenticated session
   *
   * @param cmd The command to send
   * @param data The input to the command
   * @return response
   */
  public Bytes sendSecureCmd(final Command cmd, final Bytes data) {
    Bytes resp = null;
    try {
      resp = secureTransceive(CommandUtils.getFullCommand(cmd, data));
    } catch (GeneralSecurityException e) {
      throw new YubiHsmException("Error in message contruction", e);
    }
    return CommandUtils.parseCmdResponse(cmd, resp);
  }

  private Bytes secureTransceive(final Bytes message)
      throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException,
          NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

    if (status == SessionStatus.CLOSED) {
      throw new YubiHsmException("Session is not valid");
    }

    // Setup the secret key for this message
    final SecretKey key = new SecretKeySpec(sessionEncKey, "AES");
    final byte[] iv = getIv(key);

    // Add padding
    LOG.debug("Sending message: {}", message);
    final byte[] paddedMsg = PaddingUtils.addPadding(message.toArrayUnsafe(), PADDING_BLOCK_SIZE);
    LOG.debug("Plain text message: {}", Bytes.wrap(paddedMsg));

    // Encrypt message
    final byte[] encryptedMsg = getCipherMessage(paddedMsg, key, iv, Cipher.ENCRYPT_MODE);
    LOG.debug("Encrypted message: {}", Bytes.wrap(encryptedMsg));

    // Assemble session message command without the MAC
    final byte[] sessionMsgNoMac = getSessionMessageNoMac(encryptedMsg);

    // Assemble session message command with the MAC
    final byte[] nextSessionChain = getMac(sessionMacKey, sessionChain, sessionMsgNoMac);
    final byte[] sessionMessageWithMac =
        getSessionMessageWithMac(sessionMsgNoMac, nextSessionChain);

    // Send session message command
    final Bytes sessionMsgResp = backend.transceive(Bytes.wrap(sessionMessageWithMac));
    LOG.trace("Session Message Response: {}:{}", sessionMsgResp, sessionMsgResp.size());
    // Verify response mac
    verifyResponseMac(sessionMsgResp.toArrayUnsafe(), nextSessionChain);
    LOG.debug("Response MAC successfully verified");

    // Extract command response message (encrypted)
    Bytes encryptedResp = getSessionMessageResponse(sessionMsgResp);
    LOG.debug("Encrypted response: {}:{}", encryptedResp, encryptedResp.size());

    // Decrypt command response message
    byte[] decryptedResp =
        getCipherMessage(encryptedResp.toArrayUnsafe(), key, iv, Cipher.DECRYPT_MODE);
    LOG.debug("Plain text response: {}", Bytes.wrap(decryptedResp));

    // Remove padding from command response message
    byte[] unpaddedResp = PaddingUtils.removePadding(decryptedResp, PADDING_BLOCK_SIZE);
    LOG.debug("Unpadded plain text response: {}", Bytes.wrap(unpaddedResp));

    incrementSessionCounter();
    sessionChain = nextSessionChain;

    // Return unpadded plain text command response message
    return Bytes.wrap(unpaddedResp);
  }

  private void deriveSessionKeys(final Bytes challenge) {
    sessionEncKey =
        deriveKey(
            authenticationKey.getEncryptionKey().toArrayUnsafe(),
            KEY_ENC,
            challenge.toArrayUnsafe(),
            SESSION_KEY_SIZE);
    sessionMacKey =
        deriveKey(
            authenticationKey.getMacKey().toArrayUnsafe(),
            KEY_MAC,
            challenge.toArrayUnsafe(),
            SESSION_KEY_SIZE);
    sessionRMacKey =
        deriveKey(
            authenticationKey.getMacKey().toArrayUnsafe(),
            KEY_RMAC,
            challenge.toArrayUnsafe(),
            SESSION_KEY_SIZE);
  }

  private byte[] deriveKey(
      final byte[] longTermKey, final byte type, final byte[] challenge, final int length) {
    if (length != SESSION_KEY_SIZE && length != (SESSION_KEY_SIZE / 2)) {
      throw new InvalidParameterException(
          "Length of the derived key must be either "
              + SESSION_KEY_SIZE
              + " or "
              + (SESSION_KEY_SIZE / 2)
              + " bytes long");
    }
    // 11 0 bytes + 1 byte type + 1 0 byte + 2 bytes length + 1 1 byte + challenge
    int macMsgLength = 11 + 1 + 1 + 2 + 1 + challenge.length;
    ByteBuffer input = ByteBuffer.allocate(macMsgLength);
    input.put(new byte[11]);
    input.put(type);
    input.put((byte) 0);
    input.putShort((short) (length * 8));
    input.put((byte) 1);
    input.put(challenge);
    byte[] mac = getMac(longTermKey, null, input.array());
    return Arrays.copyOfRange(mac, 0, length);
  }

  private void verifyDeviceCryptogram(final Bytes deviceCryptogram, final Bytes challenge) {
    byte[] generatedCryptogram =
        deriveKey(sessionMacKey, CARD_CRYPTOGRAM, challenge.toArrayUnsafe(), HALF_CHALLENGE_SIZE);
    if (!Bytes.wrap(generatedCryptogram).equals(deviceCryptogram)) {
      throw new YubiHsmException(Errors.AUTHENTICATION_FAILED);
    }
    LOG.debug("Card cryptogram successfully verified");
  }

  private byte[] getAuthenticateSessionMessage(final byte[] hostCryptogram) {
    // Count data lengths
    // The part of the message to mac: authentication session command + command input data length +
    // session ID + host cryptogram
    int macMsgLength =
        CommandUtils.COMMAND_ID_SIZE
            + CommandUtils.COMMAND_INPUT_LENGTH_SIZE
            + SESSION_ID_SIZE
            + hostCryptogram.length;

    // Construct the message that will be MAC:ed
    ByteBuffer bb = ByteBuffer.allocate(macMsgLength);
    bb.put(Command.AUTHENTICATE_SESSION.getCommandCode());
    bb.putShort((short) (SESSION_ID_SIZE + hostCryptogram.length + MESSAGE_MAC_SIZE));
    bb.put(sessionID);
    bb.put(hostCryptogram);
    byte[] msg = bb.array();

    // Calculate MAC of the message content
    sessionChain = getMac(sessionMacKey, new byte[CHALLENGE_SIZE], msg);
    byte[] msgMac = Arrays.copyOfRange(sessionChain, 0, MESSAGE_MAC_SIZE);

    // Add the MAC to the message content
    bb = ByteBuffer.allocate(macMsgLength + MESSAGE_MAC_SIZE);
    bb.put(msg);
    bb.put(msgMac);
    return bb.array();
  }

  /**
   * Calculate the MAC value of an input
   *
   * @param key Key used to calculate the MAC
   * @param chain 16 bytes
   * @param input Data to calculate its MAC
   * @return 16 bytes MAC
   */
  private byte[] getMac(final byte[] key, byte[] chain, byte[] input) {
    final CipherParameters params = new KeyParameter(key);
    final BlockCipher cipher = new AESEngine();
    final CMac mac = new CMac(cipher);
    mac.init(params);
    if (chain != null && chain.length > 0) {
      mac.update(chain, 0, chain.length);
    }
    mac.update(input, 0, input.length);
    byte[] out = new byte[MESSAGE_MAC_SIZE * 2];
    mac.doFinal(out, 0);
    return out;
  }

  /**
   * Sends Create Session command and returns challenge response
   *
   * @param hostChallenge 8 random bytes
   * @return Two Bytes, device challenge and device cryptogram
   */
  private List<Bytes> createSessionAndGetResponse(final Bytes hostChallenge) {
    final Bytes authKey = Bytes.ofUnsignedShort(authenticationKey.getAuthKeyId());
    final Bytes msg = Bytes.wrap(authKey, hostChallenge);
    LOG.trace("Sending session bytes: {}:{}", msg, msg.size());

    final Bytes response = CommandUtils.sendCmd(backend, Command.CREATE_SESSION, msg);
    CommandUtils.verifyResponseLength(Command.CREATE_SESSION, response.size(), 1 + CHALLENGE_SIZE);
    LOG.trace("Response: {}:{}", response, response.size());

    setSessionID(response.get(0));
    status = SessionStatus.CREATED;
    LOG.debug("Created session with SessionID: " + sessionID);

    Bytes deviceChallenge = response.slice(1, HALF_CHALLENGE_SIZE).copy();
    Bytes deviceCryptoGram = response.slice(1 + HALF_CHALLENGE_SIZE).copy();
    LOG.trace("Device Challenge: {}:{}", deviceChallenge, deviceChallenge.size());
    LOG.trace("Device Cryptogram: {}:{}", deviceCryptoGram, deviceCryptoGram.size());
    return List.of(deviceChallenge, deviceCryptoGram);
  }

  /**
   * Sets the session ID after successfully creating a session with the device
   *
   * @param b The session ID
   * @throws YubiHsmException If the specified session ID is not in the range 0-15
   */
  private void setSessionID(final byte b) throws YubiHsmException {
    if (b >= MIN_SESSION_ID && b <= MAX_SESSION_ID) { // Session ID is between 0 to 15
      sessionID = b;
    } else {
      throw new YubiHsmException("Failed to obtain a valid session ID from the device");
    }
  }

  private byte[] getIv(final SecretKey key)
      throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
          BadPaddingException, IllegalBlockSizeException {
    byte[] ivCounter = getSessionCounter();
    LOG.debug("IV counter: {}", Bytes.wrap(ivCounter));

    @SuppressWarnings("InsecureCryptoUsage")
    Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] iv = cipher.doFinal(ivCounter);
    LOG.debug("IV: {}", Bytes.wrap(iv));
    return iv;
  }

  private byte[] getSessionCounter() {
    ByteBuffer bb = ByteBuffer.allocate(SESSION_COUNTER_SIZE);
    bb.putLong(highCounter);
    bb.putLong(lowCounter);
    return bb.array();
  }

  /** Adds 1 to the session counter */
  private void incrementSessionCounter() {
    if (lowCounter == 0xFFFFFFFFFFFFFFFFL) {
      highCounter++;
    }
    lowCounter++;
  }

  private byte[] getCipherMessage(
      final byte[] message, final SecretKey encKey, final byte[] iv, final int mode)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
          InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = Cipher.getInstance("AES/CBC/NOPADDING");
    cipher.init(mode, encKey, new IvParameterSpec(iv));
    return cipher.doFinal(message);
  }

  private byte[] getSessionMessageNoMac(byte[] encMessage) {
    final int sessionMsgLength = SESSION_ID_SIZE + encMessage.length + MESSAGE_MAC_SIZE;
    final int macMessageLength =
        CommandUtils.COMMAND_ID_SIZE
            + CommandUtils.COMMAND_INPUT_LENGTH_SIZE
            + SESSION_ID_SIZE
            + encMessage.length;

    final ByteBuffer bb = ByteBuffer.allocate(macMessageLength);
    bb.put(Command.SESSION_MESSAGE.getCommandCode()).putShort((short) sessionMsgLength);
    bb.put(sessionID);
    bb.put(encMessage);
    return bb.array();
  }

  private byte[] getSessionMessageWithMac(byte[] sessionMsgNoMac, byte[] sessionChain) {
    if (sessionChain.length < MESSAGE_MAC_SIZE) {
      throw new IllegalArgumentException(
          "Session chain is too small to contain a " + MESSAGE_MAC_SIZE + " bytes MAC");
    }
    final byte[] mac = Arrays.copyOfRange(sessionChain, 0, MESSAGE_MAC_SIZE);

    final ByteBuffer bb = ByteBuffer.allocate(sessionMsgNoMac.length + MESSAGE_MAC_SIZE);
    bb.put(sessionMsgNoMac);
    bb.put(mac);
    return bb.array();
  }

  /**
   * Verifies the response from the device by comparing the response MAC with a MAC generated using
   * `challenge`
   *
   * @param response Contains the response MAC as its last 8 bytes
   * @param challenge
   * @throws YubiHsmException If response authentication fails
   */
  private void verifyResponseMac(final byte[] response, final byte[] challenge)
      throws YubiHsmException {
    if (response.length < MESSAGE_MAC_SIZE) {
      throw new IllegalArgumentException(
          "Response is too short to contain a " + MESSAGE_MAC_SIZE + " bytes MAC");
    }
    final byte[] respMac =
        Arrays.copyOfRange(response, response.length - MESSAGE_MAC_SIZE, response.length);
    final byte[] respMacMsg = Arrays.copyOfRange(response, 0, response.length - MESSAGE_MAC_SIZE);
    final byte[] fullResponseMac = getMac(sessionRMacKey, challenge, respMacMsg);
    final byte[] rmac = Arrays.copyOfRange(fullResponseMac, 0, MESSAGE_MAC_SIZE);
    if (!Arrays.equals(rmac, respMac)) {
      throw new YubiHsmException("Incorrect MAC");
    }
  }

  /**
   * Extracts the encrypted command response from the device's response to SessionMessage
   *
   * @param rawResponse The device response to SessionMessage
   * @return The device's encrypted response to the command inside SessionMessage
   * @throws YubiHsmException If the session ID returned by the device does not match this session
   *     ID or if the device had returned an error code
   */
  private Bytes getSessionMessageResponse(final Bytes rawResponse) {
    Bytes resp = CommandUtils.parseCmdResponse(Command.SESSION_MESSAGE, rawResponse);
    if (resp.get(0) != sessionID) {
      throw new YubiHsmException("Incorrect session ID");
    }

    // extract the response to the command
    // Response: 1 byte session ID + response to the command + 8 bytes MAC
    return resp.slice(1, resp.size() - MESSAGE_MAC_SIZE - 1).copy();
  }

  @Override
  public void close() {
    if (status != SessionStatus.CREATED && status != SessionStatus.AUTHENTICATED) {
      LOG.info("Session is not open. Doing nothing");
      return;
    }

    try {
      LOG.trace("Closing session {}", sessionID);
      final Bytes response = sendSecureCmd(Command.CLOSE_SESSION, Bytes.wrap(new byte[0]));
      CommandUtils.verifyResponseLength(Command.CLOSE_SESSION, response.size(), 0);
    } catch (final YubiHsmException e) {
      if (Objects.equals(e.getYubiHsmError(), Errors.INVALID_SESSION)) {
        LOG.info("YubiHSM Session {} is not valid", sessionID);
      } else {
        LOG.warn("Unexpected error while closing session", e);
      }
    } finally {
      // TODO: Destroy session keys
      destroySessionKeys();
      status = SessionStatus.CLOSED;
    }
  }

  private void destroySessionKeys() {
    if (sessionEncKey != null) {
      Arrays.fill(sessionEncKey, (byte) 0x00);
    }
    if (sessionMacKey != null) {
      Arrays.fill(sessionMacKey, (byte) 0x00);
    }
    if (sessionRMacKey != null) {
      Arrays.fill(sessionRMacKey, (byte) 0x00);
    }
    LOG.trace("Destroyed the session encryption key, MAC key and RMAC key");
  }
}
