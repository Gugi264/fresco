package dk.alexandra.fresco.tools.ot.base;

import dk.alexandra.fresco.framework.MaliciousException;
import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.framework.util.*;
import dk.alexandra.fresco.tools.ot.otextension.PseudoOtp;
import iaik.security.ec.common.ECParameterSpec;
import iaik.security.ec.common.ECStandardizedParameterFactory;
import iaik.security.ec.math.curve.ECPoint;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.MessageDigest;

public abstract class AbstractNaorPinkasOT implements Ot {

    private static final String HASH_ALGORITHM = "SHA-256";
    private final int otherId;
    private final Network network;
    protected final Drng randNum;

    private final MessageDigest hashDigest;

    abstract AbstractNaorPinkasElement generateRandomNaorPinkasElement();
    abstract AbstractNaorPinkasElement decodeElement(byte[] bytes);
    abstract BigInteger getDhModulus();
    abstract AbstractNaorPinkasElement getDhGenerator();



    public AbstractNaorPinkasOT(int otherId, Drbg randBit, Network network, DHParameterSpec params) {
        this.otherId = otherId;
        this.network = network;
        this.hashDigest = ExceptionConverter.safe(() -> MessageDigest.getInstance(HASH_ALGORITHM),
                "Missing secure, hash function which is dependent in this library");
        this.randNum = new DrngImpl(randBit);
    }

    @Override
    public void send(StrictBitVector messageZero, StrictBitVector messageOne) {
        int maxBitLength = Math.max(messageZero.getSize(), messageOne.getSize());
        Pair<byte[], byte[]> seedMessages = sendRandomOt();
        byte[] encryptedZeroMessage = PseudoOtp.encrypt(messageZero.toByteArray(),
                seedMessages.getFirst(), maxBitLength / Byte.SIZE);
        byte[] encryptedOneMessage = PseudoOtp.encrypt(messageOne.toByteArray(),
                seedMessages.getSecond(), maxBitLength / Byte.SIZE);
        network.send(otherId, encryptedZeroMessage);
        network.send(otherId, encryptedOneMessage);
    }

    @Override
    public StrictBitVector receive(boolean choiceBit) {
        byte[] seed = receiveRandomOt(choiceBit);
        byte[] encryptedZeroMessage = network.receive(otherId);
        byte[] encryptedOneMessage = network.receive(otherId);
        return recoverTrueMessage(encryptedZeroMessage, encryptedOneMessage, seed, choiceBit);
    }

    /**
     * Completes the sender's part of the Naor-Pinkas OT in order to send two random messages of the
     * length of hash digest.
     *
     * @return The two random messages sent by the sender.
     */
    private Pair<byte[], byte[]> sendRandomOt() {
        AbstractNaorPinkasElement randPoint = this.generateRandomNaorPinkasElement();
        network.send(otherId, randPoint.toByteArray());
        AbstractNaorPinkasElement publicKeyZero = this.decodeElement(network.receive(otherId));
        AbstractNaorPinkasElement publicKeyOne = publicKeyZero.inverse().groupOp(randPoint);
        Pair<AbstractNaorPinkasElement, byte[]> zeroChoiceData = encryptRandomMessage(publicKeyZero);
        Pair<AbstractNaorPinkasElement, byte[]> oneChoiceData = encryptRandomMessage(publicKeyOne);
        network.send(otherId, zeroChoiceData.getFirst().toByteArray());
        network.send(otherId, oneChoiceData.getFirst().toByteArray());
        return new Pair<>(zeroChoiceData.getSecond(), oneChoiceData.getSecond());
    }


    /**
     * Completes the receiver's part of the Naor-Pinkas OT in order to receive a random message of the
     * length of hash digest.
     *
     * @return The random message received
     */
    private byte[] receiveRandomOt(boolean choiceBit) {
        AbstractNaorPinkasElement randPoint = this.decodeElement(network.receive(otherId));
        BigInteger privateKey = randNum.nextBigInteger(getDhModulus());
        AbstractNaorPinkasElement publicKeySigma = getDhGenerator().multiply(privateKey);
        AbstractNaorPinkasElement publicKeyNotSigma = publicKeySigma.inverse().groupOp(randPoint);

        if (choiceBit == false) {
            network.send(otherId, publicKeySigma.toByteArray());
        } else {
            network.send(otherId, publicKeyNotSigma.toByteArray());
        }
        AbstractNaorPinkasElement encZero = decodeElement(network.receive(otherId));
        AbstractNaorPinkasElement encOne = decodeElement(network.receive(otherId));
        byte[] message;
        if (choiceBit == false) {
            message = decryptRandomMessage(encZero, privateKey);
        } else {
            message = decryptRandomMessage(encOne, privateKey);
        }
        return message;
    }

    /**
     * Completes the internal Naor-Pinkas encryption.
     * <p>
     * Given a "public key" as input this method constructs an encryption of a random message. Both
     * the encryption and random message are returned.
     * </p>
     *
     * @param publicKey The public key to encrypt with
     * @return A pair where the first element is the ciphertext and the second element is the
     *         plaintext.
     */
    private Pair<AbstractNaorPinkasElement, byte[]> encryptRandomMessage(AbstractNaorPinkasElement publicKey) {

        BigInteger r = randNum.nextBigInteger(getDhModulus());
        AbstractNaorPinkasElement cipherText = getDhGenerator().multiply(r);
        AbstractNaorPinkasElement toHash = publicKey.multiply(r);
        byte[] message = hashDigest.digest(toHash.toByteArray());
        return new Pair<>(cipherText, message);
    }

    /**
     * Completes the internal Naor-Pinkas decryption.
     *
     * @param cipher The ciphertext to decrypt
     * @param privateKey The private key to use for decryption
     * @return The plain message
     */
    private byte[] decryptRandomMessage(AbstractNaorPinkasElement cipher, BigInteger privateKey) {
        AbstractNaorPinkasElement toHash = cipher.multiply(privateKey);
        return hashDigest.digest(toHash.toByteArray());
    }

    /**
     * Receive one-time padded OT messages and remove the pad of the one of the messages chosen in the
     * OT.
     *
     * @param encryptedZeroMessage The one-time padded zero-message
     * @param encryptedOneMessage the one-time padded one-message
     * @param seed The seed used for padding of one of the messages
     * @param choiceBit A bit indicating which message the seed matches. False implies message zero
     *        and true message one.
     * @return The unpadded message as a StrictBitVector
     */
    private StrictBitVector recoverTrueMessage(byte[] encryptedZeroMessage,
                                               byte[] encryptedOneMessage, byte[] seed, boolean choiceBit) {
        if (encryptedZeroMessage.length != encryptedOneMessage.length) {
            throw new MaliciousException("The length of the two choice messages is not equal");
        }
        byte[] unpaddedMessage;
        if (choiceBit == false) {
            unpaddedMessage = PseudoOtp.decrypt(encryptedZeroMessage, seed);
        } else {
            unpaddedMessage = PseudoOtp.decrypt(encryptedOneMessage, seed);
        }
        return new StrictBitVector(unpaddedMessage);
    }



}
