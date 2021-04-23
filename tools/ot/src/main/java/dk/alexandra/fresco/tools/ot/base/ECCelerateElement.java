package dk.alexandra.fresco.tools.ot.base;

import iaik.security.ec.math.curve.ECPoint;

import java.math.BigInteger;

public class ECCelerateElement implements InterfaceOtElement<ECCelerateElement> {

    private final ECPoint point;

    public ECCelerateElement(ECPoint point) {
        this.point = point;
    }

    // input the hashed message
    ECCelerateElement hashToPoint(byte[] input, ECPoint generator) {
        BigInteger random = new BigInteger(input);
        return new ECCelerateElement(generator.multiplyPoint(random));
    }

    @Override
    public byte[] toByteArray() {
        return this.point.encodePoint();
    }

    @Override
    public ECCelerateElement groupOp(ECCelerateElement other) {
        ECPoint tmpPoint = this.point.clone();
        return new ECCelerateElement(tmpPoint.addPoint(other.point));
    }

    @Override
    public ECCelerateElement inverse() {
        return new ECCelerateElement(this.point.clone().negatePoint());
    }

    @Override
    public ECCelerateElement exponentiation(BigInteger n) {
        ECPoint tmpPoint = this.point.clone();
        return new ECCelerateElement(tmpPoint.multiplyPoint(n));
    }

    @Override
    public ECCelerateElement hashToElement(String DST) {
        return null;
    }


}
