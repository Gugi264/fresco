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
import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * Uses Chou-Orlandi with fixes as seen in https://eprint.iacr.org/2017/1011
 */
public abstract class AbstractChouOrlandiOT<T extends InterfaceNaorPinkasElement<T>> implements Ot {

  private static final String HASH_ALGORITHM = "SHA-256";
  private final int otherId;
  private final Network network;
  protected final Drng randNum;

  private final MessageDigest hashDigest;


  /**
   * Decodes an encoded element
   * @param bytes the encoded element represented in bytes
   * @return the decoded element
   */
  abstract T decodeElement(byte[] bytes);

  abstract T hashToElement(T input);

  abstract T getGenerator();

  abstract BigInteger getDhModulus();

  public AbstractChouOrlandiOT(int otherId, Drbg randBit, Network network) {
    this.otherId = otherId;
    this.network = network;
    this.randNum = new DrngImpl(randBit);
    this.hashDigest = ExceptionConverter.safe(() -> MessageDigest.getInstance(HASH_ALGORITHM),
        "Missing secure, hash function which is dependent in this library");
  }

  @Override
  public void send(StrictBitVector messageZero, StrictBitVector messageOne) {
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
   * Completes the receiver's part of the Naor-Pinkas OT in order to receive a random message of the
   * length of hash digest.
   *
   * @return The random message received
   */
  private byte[] receiveRandomOt(boolean choiceBit) {
    //TODO: check if in group
    // S
    T S = this.decodeElement(network.receive(otherId));
    // T = G(S)
    T T = hashToElement(S);
    // R = T^c*g^x
    // if c = 0 -> R = g^x
    // x
    BigInteger x = randNum.nextBigInteger(getDhModulus());
    T R;
    //TODO: constant time problem?
    if (choiceBit == false) {
      R = T.exponentiation(BigInteger.ZERO).groupOp(getGenerator().exponentiation(x));
    }
    else {
      R = T.exponentiation(BigInteger.ONE).groupOp(getGenerator().exponentiation(x));
    }
    network.send(otherId, R.toByteArray());

    // k = H(S, R, S^x)
    byte[] key;
    hashDigest.update(S.toByteArray());
    hashDigest.update(R.toByteArray());
    hashDigest.update(S.exponentiation(x).toByteArray());
    key = hashDigest.digest();
    return key;
  }

  /**
   * Completes the sender's part of the Chou-Orlandi OT in order to send two random messages of the
   * length of hash digest.
   *
   * @return The two random messages sent by the sender.
   */
  private Pair<byte[], byte[]> sendRandomOt() {
    // y
    BigInteger y = randNum.nextBigInteger(getDhModulus());
    // S
    T S = this.getGenerator().exponentiation(y);
    network.send(otherId, S.toByteArray());
    // T = G(S)
    T T = hashToElement(S);
    byte[] rBytes = network.receive(otherId);
    // R
    //TODO: check if in group
    T R = decodeElement(rBytes);


    byte[] k0Hash, k1Hash;
    hashDigest.update(S.toByteArray());
    hashDigest.update(R.toByteArray());
    // R^y*T^(-jy) with j = 0:
    // R^y * T^(-0y) == R^y
    hashDigest.update(R.exponentiation(y).toByteArray());
    k0Hash = hashDigest.digest();

    hashDigest.update(S.toByteArray());
    hashDigest.update(R.toByteArray());
    // R^y*T^(-jy) with j = 1:
    // R^y * T^(-1y) == (R + (-T)) * y
    hashDigest.update((R.groupOp(T.inverse())).exponentiation(y).toByteArray());
    k1Hash = hashDigest.digest();

    // sending of the Encrypted messages is done in outer function
    return new Pair<>(k0Hash, k1Hash);
  }


}
