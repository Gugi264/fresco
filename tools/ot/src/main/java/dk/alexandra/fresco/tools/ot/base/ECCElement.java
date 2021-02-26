package dk.alexandra.fresco.tools.ot.base;

import iaik.security.ec.math.curve.ECPoint;

import java.math.BigInteger;

public class ECCElement implements AbstractNaorPinkasElement {
    ECPoint point;

    public ECCElement(ECPoint point) {
        this.point = point;
    }

    @Override
    public byte[] toByteArray() {
        return this.point.encodePoint();
    }

    @Override
    public AbstractNaorPinkasElement groupOp(AbstractNaorPinkasElement other) {
        ECCElement otherEcc = (ECCElement) other;
        ECPoint tmpPoint = this.point.clone();
        return new ECCElement(tmpPoint.addPoint(otherEcc.point));
    }

    @Override
    public AbstractNaorPinkasElement inverse() {
        return new ECCElement(this.point.clone().negatePoint());
    }

    @Override
    public AbstractNaorPinkasElement multiply(BigInteger other) {
        ECPoint tmpPoint = this.point.clone();
        return new ECCElement(tmpPoint.multiplyPoint(other));
    }

}
