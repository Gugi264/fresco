package dk.alexandra.fresco.tools.ot.base;

import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.util.Drbg;
import iaik.security.ec.common.ECParameterSpec;
import iaik.security.ec.common.ECStandardizedParameterFactory;
import iaik.security.ec.math.curve.ECPoint;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class ECCNaorPinkas extends AbstractNaorPinkasOT{

    /**
     * The modulus of the Diffie-Hellman group used in the OT.
     */
    private final BigInteger dhModulus;
    /**
     * The generator of the Diffie-Hellman group used in the OT.
     */
    private final ECPoint dhGenerator;

    private final ECParameterSpec ecParameterSpec;

    private final iaik.security.ec.math.curve.EllipticCurve curve;


    public ECCNaorPinkas(int otherId, Drbg randBit, Network network, DHParameterSpec params) {
        super(otherId, randBit, network, params);
        this.ecParameterSpec = ECStandardizedParameterFactory.getPrimeCurveParametersByBitLength(256);
        this.curve = ecParameterSpec.getCurve().getIAIKCurve();
        this.dhModulus = this.curve.getOrder();
        this.dhGenerator = curve.newPoint(ecParameterSpec.getGenerator());
        iaik.security.ec.math.curve.ECPoint.allFunctionsInPlace(true);
    }


    @Override
    public AbstractNaorPinkasElement decodeElement(byte[] bytes) {
        ECPoint tmp;
        try {
            tmp = this.curve.decodePoint(bytes);
        }
        catch (Exception e) {
            throw new RuntimeException("Error decoding Element in ECCNaorPinkas");
        }
        return new ECCElement(tmp);

    }


    @Override
    AbstractNaorPinkasElement generateRandomNaorPinkasElement() {
        return new ECCElement(this.dhGenerator.clone().multiplyPoint(this.randNum.nextBigInteger(this.dhModulus)));
    }

    @Override
    BigInteger getDhModulus() {
        return this.dhModulus;
    }

    @Override
    AbstractNaorPinkasElement getDhGenerator() {
        return new ECCElement(this.dhGenerator);
    }


}
