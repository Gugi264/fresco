package dk.alexandra.fresco.tools.ot.base;

import iaik.security.ec.math.curve.ECPoint;

import java.math.BigInteger;

public interface AbstractNaorPinkasElement {

    abstract byte[] toByteArray();
    abstract AbstractNaorPinkasElement groupOp(AbstractNaorPinkasElement other);
    abstract AbstractNaorPinkasElement inverse();
    abstract AbstractNaorPinkasElement multiply(BigInteger other);


}
