package dk.alexandra.fresco.tools.ot.base;

import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.util.Drbg;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.math.ec.ECCurve;

import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

public class BouncyCastleNaorPinkas extends AbstractNaorPinkasOT {

  /**
   * The modulus of the Diffie-Hellman group used in the OT.
   */
  private final BigInteger dhModulus;
  /**
   * The generator of the Diffie-Hellman group used in the OT.
   */
  private final org.bouncycastle.math.ec.ECPoint dhGenerator;

  private final ECCurve curve;

  public BouncyCastleNaorPinkas(int otherId, Drbg randBit, Network network) {
    super(otherId, randBit, network);
    X9ECParameters ecP = CustomNamedCurves.getByName("P-256");
    ECParameterSpec ecSpec = EC5Util.convertToSpec(ecP);
    this.curve = ecP.getCurve();
    this.dhModulus = curve.getOrder();
    ECPoint tmpGenerator = ecSpec.getGenerator();
    this.dhGenerator = curve.createPoint(tmpGenerator.getAffineX(), tmpGenerator.getAffineY());
  }

  @Override
  InterfaceNaorPinkasElement generateRandomNaorPinkasElement() {
    return new BouncyCastleECCElement(
        this.dhGenerator.multiply(this.randNum.nextBigInteger(this.dhModulus)));
  }

  @Override
  InterfaceNaorPinkasElement decodeElement(byte[] bytes) {
    org.bouncycastle.math.ec.ECPoint tmp = this.curve.decodePoint(bytes);
    return new BouncyCastleECCElement(this.curve.decodePoint(bytes));
  }

  @Override
  BigInteger getDhModulus() {
    return this.dhModulus;
  }

  @Override
  InterfaceNaorPinkasElement getDhGenerator() {
    return new BouncyCastleECCElement(this.dhGenerator);
  }
}
