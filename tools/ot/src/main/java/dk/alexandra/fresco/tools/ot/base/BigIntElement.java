package dk.alexandra.fresco.tools.ot.base;

import java.math.BigInteger;

public class BigIntElement implements AbstractNaorPinkasElement {

    BigInteger element;
    BigInteger dhModulus;

    public BigIntElement(BigInteger element, BigInteger dhModulus) {
        this.element = element;
        this.dhModulus = dhModulus;
    }

    @Override
    public byte[] toByteArray() {
        return this.element.toByteArray();
    }

    @Override
    public AbstractNaorPinkasElement groupOp(AbstractNaorPinkasElement other) {
        BigInteger otherBigInt = ((BigIntElement) other).element;
        return new BigIntElement(this.element.multiply(otherBigInt), this.dhModulus);
    }

    @Override
    public AbstractNaorPinkasElement inverse() {
        return new BigIntElement(this.element.modInverse(this.dhModulus), this.dhModulus);
    }

    @Override
    //modPow in this case
    public AbstractNaorPinkasElement multiply(BigInteger other) {
        return new BigIntElement(this.element.modPow(other, this.dhModulus), this.dhModulus);
    }
}
