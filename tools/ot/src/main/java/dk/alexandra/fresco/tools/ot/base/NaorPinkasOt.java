package dk.alexandra.fresco.tools.ot.base;

import dk.alexandra.fresco.framework.MaliciousException;
import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.util.Drbg;
import dk.alexandra.fresco.framework.util.Drng;
import dk.alexandra.fresco.framework.util.DrngImpl;
import dk.alexandra.fresco.framework.util.ExceptionConverter;
import dk.alexandra.fresco.framework.util.Pair;
import dk.alexandra.fresco.framework.util.StrictBitVector;
import dk.alexandra.fresco.tools.ot.otextension.PseudoOtp;
import iaik.security.ec.common.ECParameterSpec;
import iaik.security.ec.common.ECStandardizedParameterFactory;
import iaik.security.ec.common.PointEncoders;
import iaik.security.ec.math.curve.Coordinate;
import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.math.curve.PrimeMontgomeryCurveFactory;
import iaik.security.ec.math.field.AbstractPrimeField;
import iaik.security.ec.math.field.PrimeFieldByPrimeFactory;
import iaik.security.ec.math.field.PrimeFieldElement;

import java.math.BigInteger;
import java.security.MessageDigest;
import javax.crypto.spec.DHParameterSpec;

/**
 * Implementation of the Naor-Pinkas OT.
 */
public class NaorPinkasOt implements Ot {
  private static final String HASH_ALGORITHM = "SHA-256";
  private final int otherId;
  private final Network network;
  private final Drng randNum;
  private final MessageDigest hashDigest;
  /**
   * The modulus of the Diffie-Hellman group used in the OT.
   */
  private final BigInteger dhModulus;
  /**
   * The generator of the Diffie-Hellman group used in the OT.
   */
  private final ECPoint dhGenerator;
  //private final BigInteger dhGenerator;

  private final ECParameterSpec ecParameterSpec;
  private final iaik.security.ec.math.curve.EllipticCurve curve;

  /**
   * Constructs a Naor-Pinkas OT instance using prespecified Diffie-Hellman parameters.
   *
   * @param otherId The ID of the other party
   * @param randBit The calling party's secure randomness generator
   * @param network The underlying network to use
   * @param params The Diffie-Hellman parameters to use
   */
  public NaorPinkasOt(int otherId, Drbg randBit, Network network, DHParameterSpec params) {
    this.otherId = otherId;
    this.network = network;
    this.ecParameterSpec = ECStandardizedParameterFactory.getPrimeCurveParametersByBitLength(256);
    this.hashDigest = ExceptionConverter.safe(() -> MessageDigest.getInstance(HASH_ALGORITHM),
            "Missing secure, hash function which is dependent in this library");
    /*this.dhModulus = params.getP();
    this.dhGenerator = params.getG();*/
    this.curve = ecParameterSpec.getCurve().getIAIKCurve();
    this.dhModulus = this.curve.getOrder();
    this.dhGenerator = this.curve.getGenerator();
    this.randNum = new DrngImpl(randBit);
    iaik.security.ec.math.curve.ECPoint.allFunctionsInPlace(true);


  }

  @Override
  public void
  send(StrictBitVector messageZero, StrictBitVector messageOne) {
    System.out.println("in send");
    int maxBitLength = Math.max(messageZero.getSize(), messageOne.getSize());
    Pair<byte[], byte[]> seedMessages = sendRandomOt();
    byte[] encryptedZeroMessage = PseudoOtp.encrypt(messageZero.toByteArray(),
        seedMessages.getFirst(), maxBitLength / Byte.SIZE);
    byte[] encryptedOneMessage = PseudoOtp.encrypt(messageOne.toByteArray(),
        seedMessages.getSecond(), maxBitLength / Byte.SIZE);
    network.send(otherId, encryptedZeroMessage);
    network.send(otherId, encryptedOneMessage);
  }

  @Override
  public StrictBitVector receive(boolean choiceBit) {
    byte[] seed = receiveRandomOt(choiceBit);
    byte[] encryptedZeroMessage = network.receive(otherId);
    byte[] encryptedOneMessage = network.receive(otherId);
    return recoverTrueMessage(encryptedZeroMessage, encryptedOneMessage, seed, choiceBit);
  }

  /**
   * Receive one-time padded OT messages and remove the pad of the one of the messages chosen in the
   * OT.
   *
   * @param encryptedZeroMessage The one-time padded zero-message
   * @param encryptedOneMessage the one-time padded one-message
   * @param seed The seed used for padding of one of the messages
   * @param choiceBit A bit indicating which message the seed matches. False implies message zero
   *        and true message one.
   * @return The unpadded message as a StrictBitVector
   */
  private StrictBitVector recoverTrueMessage(byte[] encryptedZeroMessage,
      byte[] encryptedOneMessage, byte[] seed, boolean choiceBit) {
    if (encryptedZeroMessage.length != encryptedOneMessage.length) {
      throw new MaliciousException("The length of the two choice messages is not equal");
    }
    byte[] unpaddedMessage;
    if (choiceBit == false) {
      unpaddedMessage = PseudoOtp.decrypt(encryptedZeroMessage, seed);
    } else {
      unpaddedMessage = PseudoOtp.decrypt(encryptedOneMessage, seed);
    }
    return new StrictBitVector(unpaddedMessage);
  }

  /**
   * Completes the sender's part of the Naor-Pinkas OT in order to send two random messages of the
   * length of hash digest.
   *
   * @return The two random messages sent by the sender.
   */
  private Pair<byte[], byte[]> sendRandomOt() {

    ECPoint randPoint = this.curve.multiplyPoint(this.dhGenerator, randNum.nextBigInteger(dhModulus));
    System.out.println("in sendRandomOt");
    System.out.println(randPoint.toString());
    System.out.flush();
    //BigInteger c = randNum.nextBigInteger(dhModulus);

    network.send(otherId, this.curve.encodePoint(randPoint));
    //BigInteger publicKeyZero = new BigInteger(network.receive(otherId));
    ECPoint publicKeyZero;
    try{
      publicKeyZero = this.curve.decodePoint(network.receive(otherId));
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
    // BigInteger publicKeyOne = publicKeyZero.modInverse(dhModulus).multiply(c);
    ECPoint publicKeyOne = publicKeyZero.clone().negatePoint().addPoint(randPoint);
    Pair<ECPoint, byte[]> zeroChoiceData = encryptRandomMessage(publicKeyZero);
    Pair<ECPoint, byte[]> oneChoiceData = encryptRandomMessage(publicKeyOne);
    network.send(otherId, zeroChoiceData.getFirst().encodePoint());
    network.send(otherId, oneChoiceData.getFirst().encodePoint());
    return new Pair<>(zeroChoiceData.getSecond(), oneChoiceData.getSecond());
  }

  /**
   * Completes the receiver's part of the Naor-Pinkas OT in order to receive a random message of the
   * length of hash digest.
   *
   * @return The random message received
   */
  private byte[] receiveRandomOt(boolean choiceBit) {
    System.out.println("in receive");
    System.out.flush();
    ECPoint randPoint;
    try{
      randPoint = this.curve.decodePoint(network.receive(otherId));
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
    //ECPoint privateKey = this.curve.getGenerator().multiplyPoint( randNum.nextBigInteger(dhModulus));
    BigInteger privateKey = randNum.nextBigInteger(dhModulus);
    ECPoint publicKeySigma = this.dhGenerator.multiplyPoint(privateKey);
    ECPoint publicKeyNotSigma = publicKeySigma.clone().negatePoint().addPoint(randPoint);
    //BigInteger publicKeySigma = dhGenerator.modPow(privateKey, dhModulus);
    //BigInteger publicKeyNotSigma = publicKeySigma.modInverse(dhModulus).multiply(c);
    if (choiceBit == false) {
      network.send(otherId, publicKeySigma.encodePoint());
    } else {
      network.send(otherId, publicKeyNotSigma.encodePoint());
    }
    //BigInteger encZero = new BigInteger(network.receive(otherId));
    //BigInteger encOne = new BigInteger(network.receive(otherId));
    ECPoint encZero;
    ECPoint encOne;
    try{
      encZero = this.curve.decodePoint(network.receive(otherId));
      encOne = this.curve.decodePoint(network.receive(otherId));
    }
    catch (Exception e)
    {
      throw  new RuntimeException(e);
    }
    byte[] message;
    if (choiceBit == false) {
      message = decryptRandomMessage(encZero, privateKey);
    } else {
      message = decryptRandomMessage(encOne, privateKey);
    }
    return message;
  }

  /**
   * Completes the internal Naor-Pinkas encryption.
   * <p>
   * Given a "public key" as input this method constructs an encryption of a random message. Both
   * the encryption and random message are returned.
   * </p>
   *
   * @param publicKey The public key to encrypt with
   * @return A pair where the first element is the ciphertext and the second element is the
   *         plaintext.
   */
  private Pair<ECPoint, byte[]> encryptRandomMessage(ECPoint publicKey) {
    BigInteger r = randNum.nextBigInteger(dhModulus);
    ECPoint cipherText = dhGenerator.multiplyPoint(r);
    ECPoint toHash = this.curve.multiplyPoint(publicKey, r);
    byte[] message = hashDigest.digest(toHash.encodePoint());
    return new Pair<>(cipherText, message);
  }

  /**
   * Completes the internal Naor-Pinkas decryption.
   *
   * @param cipher The ciphertext to decrypt
   * @param privateKey The private key to use for decryption
   * @return The plain message
   */
  private byte[] decryptRandomMessage(ECPoint cipher, BigInteger privateKey) {
    //BigInteger toHash = cipher.modPow(privateKey, dhModulus);
    ECPoint toHash = this.curve.multiplyPoint(cipher, privateKey);
    return hashDigest.digest(toHash.encodePoint());
  }
}
