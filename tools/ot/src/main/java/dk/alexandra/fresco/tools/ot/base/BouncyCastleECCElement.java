package dk.alexandra.fresco.tools.ot.base;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class BouncyCastleECCElement implements AbstractNaorPinkasElement{

    ECPoint point;

    public BouncyCastleECCElement(ECPoint point) {
        this.point = point;
    }

    @Override
    public byte[] toByteArray() {
        return point.getEncoded(false);
    }

    @Override
    public AbstractNaorPinkasElement groupOp(AbstractNaorPinkasElement other) {
        BouncyCastleECCElement otherBC = (BouncyCastleECCElement) other;
        return new BouncyCastleECCElement(this.point.add(otherBC.point));
    }

    @Override
    public AbstractNaorPinkasElement inverse() {
        return new BouncyCastleECCElement(this.point.negate());
    }

    @Override
    public AbstractNaorPinkasElement multiply(BigInteger other) {
        return new BouncyCastleECCElement(this.point.multiply(other));
    }
}
