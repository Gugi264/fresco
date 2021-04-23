package dk.alexandra.fresco.tools.ot.base;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import static org.bouncycastle.pqc.math.linearalgebra.BigEndianConversions.I2OSP;

public class BigIntElement implements InterfaceOtElement<BigIntElement> {

  private final BigInteger element;
  private final BigInteger dhModulus;

  public BigIntElement(BigInteger element, BigInteger dhModulus) {
    this.element = element;
    this.dhModulus = dhModulus;
  }

  @Override
  public byte[] toByteArray() {
    return this.element.toByteArray();
  }

  @Override
  public BigIntElement groupOp(BigIntElement other) {
    return new BigIntElement(this.element.multiply(other.element), this.dhModulus);
  }

  @Override
  public BigIntElement inverse() {
    return new BigIntElement(this.element.modInverse(this.dhModulus), this.dhModulus);
  }

  @Override
  //modPow in this case
  public BigIntElement exponentiation(BigInteger n) {
    return new BigIntElement(this.element.modPow(n, this.dhModulus), this.dhModulus);
  }

    /**
     * Only needed for Chou Orlandi
     *
     * Hashing to finite fields according to [1] in point 5.2
     * [1] https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06
     * @return a new BigIntElement
     */
    @Override
  public BigIntElement hashToElement(String DST) {
      byte[] msg = this.toByteArray();
      //security parameter in bits //TODO: its probably much higher
      int k = 256;
      int L = (int) Math.ceil((Math.ceil(this.dhModulus.bitLength()) + k) / 8);

      //start of algorithm, we only need one element, and m is 1, so L = lenInBytes
      int lenInByts = L;
      SHAKEDigest xof = new SHAKEDigest(256);
      xof.update(msg, 0, msg.length);
      xof.update(I2OSP(lenInByts, 2), 0, 2);
      xof.update(I2OSP(DST.getBytes(StandardCharsets.UTF_8).length, 1), 0, 1);
      xof.update(DST.getBytes(StandardCharsets.UTF_8), 0, DST.getBytes(StandardCharsets.UTF_8).length);
      byte[] pseudoRandomBytes = new byte[lenInByts];
      xof.doFinal(pseudoRandomBytes, 0, lenInByts);
      return new BigIntElement(this.element, dhModulus);
  }

}
