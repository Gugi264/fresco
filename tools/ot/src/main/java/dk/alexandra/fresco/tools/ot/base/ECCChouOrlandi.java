package dk.alexandra.fresco.tools.ot.base;

import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.util.Drbg;
import iaik.security.ec.common.ECParameterSpec;
import iaik.security.ec.common.ECStandardizedParameterFactory;
import iaik.security.ec.math.curve.ECPoint;
import iaik.security.ec.provider.ECCelerate;

import java.math.BigInteger;

/**
 * Needs the ECCelerate and the JCE dependency from the OT pom.xml
 * Get from https://jce.iaik.tugraz.at
 */
public class ECCChouOrlandi extends AbstractChouOrlandiOT<ECCelerateElement>{

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


    public ECCChouOrlandi(int otherId, Drbg randBit, Network network) {
        super(otherId, randBit, network);
        ECCelerate.addAsProvider();
        this.ecParameterSpec = ECStandardizedParameterFactory.getPrimeCurveParametersByBitLength(256);
        this.curve = ecParameterSpec.getCurve().getIAIKCurve();
        this.dhModulus = this.curve.getOrder();
        this.dhGenerator = curve.newPoint(ecParameterSpec.getGenerator());
        iaik.security.ec.math.curve.ECPoint.allFunctionsInPlace(true);

    }


    @Override
    public ECCelerateElement decodeElement(byte[] bytes) {
        ECPoint tmp;
        try {
            tmp = this.curve.decodePoint(bytes);
        } catch (Exception e) {
            throw new RuntimeException("Error decoding Element in ECCNaorPinkas");
        }
        return new ECCelerateElement(tmp);
    }


    @Override
    ECCelerateElement getGenerator() {
       return new ECCelerateElement(this.dhGenerator.clone());
    }

    @Override
    BigInteger getDhModulus() {
        return this.dhModulus;
    }

    @Override
    ECCelerateElement multiplyWithGenerator(BigInteger input) {
       return new ECCelerateElement(this.dhGenerator.clone().multiplyPoint(input));
    }
}