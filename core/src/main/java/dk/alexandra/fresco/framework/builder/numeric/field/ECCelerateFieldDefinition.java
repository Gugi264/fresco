package dk.alexandra.fresco.framework.builder.numeric.field;

import dk.alexandra.fresco.framework.util.StrictBitVector;
import iaik.security.ec.math.field.AbstractPrimeField;
import iaik.security.ec.math.field.PrimeFieldByPrimeFactory;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public final class ECCelerateFieldDefinition implements FieldDefinition {

  AbstractPrimeField primeField;

  /**
   * modulus has to be a prime, as we are using a prime field
   * @param modulus
   */
  public ECCelerateFieldDefinition(BigInteger modulus) {
    this.primeField = PrimeFieldByPrimeFactory.getField(modulus);
  }

  @Override
  public FieldElement createElement(long value) {
    return ECCelerateFieldElement.create(value, primeField);
  }

  @Override
  public FieldElement createElement(String value) {
    System.out.println("create element with string not implemented");
    return null;
  }

  @Override
  public FieldElement createElement(BigInteger value) {
    return ECCelerateFieldElement.create(value, this.primeField);
  }

  @Override
  public BigInteger getModulus() {
    return this.primeField.getP();
  }

  @Override
  public int getBitLength() {
    return this.primeField.getFieldSize();
  }

  @Override
  public StrictBitVector convertToBitVector(FieldElement fieldElement) {
    FieldUtils utils = new FieldUtils(primeField.getP().bitLength(), this::createElement,
        ECCelerateFieldElement::extractValue);
    return utils.convertToBitVector(fieldElement);
  }

  @Override
  public BigInteger convertToUnsigned(FieldElement value) {
    return ECCelerateFieldElement.extractValue(value);
  }

  @Override
  public BigInteger convertToSigned(BigInteger asUnsigned) {
    return FieldUtils.convertRepresentation(asUnsigned, getModulus(), getModulus().shiftRight(1));
  }

  @Override
  public byte[] serialize(FieldElement object) {
    return ECCelerateFieldElement.extractByteArray(object);
  }

  @Override
  public byte[] serialize(List<FieldElement> objects) {
    int byteArrayLength = (primeField.getP().bitLength() + 7) >>> 3;
    ByteBuffer target = ByteBuffer.allocate(byteArrayLength*objects.size());
    for (FieldElement o : objects)
    {
      target.put(serialize(o));
    }
    return target.array();
  }

  @Override
  public FieldElement deserialize(byte[] bytes) {
    return ECCelerateFieldElement.create(bytes, this.primeField);
  }

  @Override
  public List<FieldElement> deserializeList(byte[] bytes) {
    int byteArrayLength = (primeField.getP().bitLength() + 7) >>> 3;
    List<FieldElement> target = new ArrayList<FieldElement>(bytes.length/byteArrayLength);
    ByteBuffer buffer = ByteBuffer.wrap(bytes);
    byte[] tmp = new byte[byteArrayLength];
    for (int i = 0; i < bytes.length; i+=byteArrayLength) {
      buffer.get(tmp, 0, byteArrayLength);
      target.add(deserialize(tmp));
    }
    return target;
  }
}
