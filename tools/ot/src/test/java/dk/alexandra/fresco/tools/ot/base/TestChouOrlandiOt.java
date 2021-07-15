package dk.alexandra.fresco.tools.ot.base;

import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.util.*;
import dk.alexandra.fresco.tools.helper.HelperForTests;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.spec.DHParameterSpec;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class TestChouOrlandiOt {

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                {ECCChouOrlandi.class},
                {BouncyCastleChouOrlandi.class},
                {BigIntChouOrlandi.class}
        });
    }


    private Class testClass;

    public TestChouOrlandiOt(Class testClass) {
        this.testClass = testClass;
    }

    private AbstractChouOrlandiOT ot;
    private Drng randNum;
    private DHParameterSpec staticSpec;

    /**
     * Construct a NaorPinkasOt instance based on some static Diffie-Hellman parameters.
     *
     * @throws SecurityException Thrown if it is not possible to change private method visibility
     * @throws NoSuchMethodException Thrown if it is not possible to change private method visibility
     */
    @Before
    public void setup()
            throws NoSuchMethodException, SecurityException, IllegalAccessException, InvocationTargetException, InstantiationException {
        Drbg randBit = new AesCtrDrbg(HelperForTests.seedOne);
        randNum = new DrngImpl(randBit);
        // fake network
        Network network = new Network() {
            @Override
            public void send(int partyId, byte[] data) {}

            @Override
            public byte[] receive(int partyId) {
                return null;
            }

            @Override
            public int getNoOfParties() {
                return 0;
            }
        };
        staticSpec = DhParameters.getStaticDhParams();
        Class clazz = this.testClass;
        Constructor[] constructors = clazz.getConstructors();
        this.ot = (AbstractChouOrlandiOT) constructors[0]
                .newInstance(2, randBit, network);
        // Change visibility of private methods so they can be tested
    }



    /**** POSITIVE TESTS. ****/

    @Test
    public void testHashToFieldElement() throws InvocationTargetException, IllegalAccessException {
        Method hashToFieldElementMethod = getMethodFromAbstractClass("hashToFieldElement");
        // Remove private
        hashToFieldElementMethod.setAccessible(true);
        InterfaceOtElement generator = ot.getGenerator();
        InterfaceOtElement hashedElement = (InterfaceOtElement) hashToFieldElementMethod.invoke(generator, "RandomString");


    }

    @SuppressWarnings("unchecked")
    @Test
    public void testEncDec()
            throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        BigInteger privateKey = randNum.nextBigInteger(staticSpec.getP());
        InterfaceOtElement publicKey = ot.getGenerator().exponentiation(privateKey);
        Pair<InterfaceOtElement, byte[]> encryptionData =
                (Pair<InterfaceOtElement, byte[]>) encryptMessage.invoke(ot, publicKey);
        byte[] message = encryptionData.getSecond();
        // Sanity check that the byte array gets initialized, i.e. is not the 0-array
        assertFalse(Arrays.equals(new byte[32], message));
        byte[] decryptedMessage =
                (byte[]) decryptMessage.invoke(ot, encryptionData.getFirst(), privateKey);
        assertArrayEquals(message, decryptedMessage);
    }

    /**** NEGATIVE TESTS. ****/
    @SuppressWarnings("unchecked")
    @Test
    public void testFailedEncDec()
            throws IllegalAccessException, IllegalArgumentException, InvocationTargetException {
        BigInteger privateKey = randNum.nextBigInteger(staticSpec.getP());
        InterfaceOtElement publicKey = ot.getGenerator().exponentiation(privateKey);
        Pair<InterfaceOtElement, byte[]> encryptionData =
                (Pair<InterfaceOtElement, byte[]>) encryptMessage.invoke(ot, publicKey);
        byte[] message = encryptionData.getSecond();
        // Sanity check that the byte array gets initialized, i.e. is not the 0-array
        assertEquals(32, message.length);
        assertFalse(Arrays.equals(new byte[32], message));
        message[(32) - 1] ^= 0x01;
        byte[] decryptedMessage =
                (byte[]) decryptMessage.invoke(ot, encryptionData.getFirst(), privateKey);
        assertFalse(Arrays.equals(message, decryptedMessage));
    }

    @Test
    public void testUnequalLengthMessages() throws SecurityException, IllegalArgumentException,
            IllegalAccessException, NoSuchMethodException {
        Method method = getMethodFromAbstractClass("recoverTrueMessage");
        // Remove private
        method.setAccessible(true);
        boolean thrown = false;
        try {
            method.invoke(ot, new byte[] { 0x42, 0x42 }, new byte[] { 0x42 }, new byte[] { 0x42 }, true);
        } catch (InvocationTargetException e) {
            assertEquals("The length of the two choice messages is not equal",
                    e.getTargetException().getMessage());
            thrown = true;
        }
        assertTrue(thrown);
    }


    private Method getMethodFromAbstractClass(String methodToSearch) {
        Class<?> clazz = this.testClass;
        while (clazz != null) {
            Method[] methods = clazz.getDeclaredMethods();
            for (Method method : methods) {
                // Test any other things about it beyond the name...
                if (method.getName().equals(methodToSearch)) {
                    return method;
                }
            }
            clazz = clazz.getSuperclass();
        }
        return null;
    }
}

