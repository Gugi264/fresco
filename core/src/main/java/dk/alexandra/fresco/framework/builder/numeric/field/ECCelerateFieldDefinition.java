package dk.alexandra.fresco.framework.builder.numeric.field;

import dk.alexandra.fresco.framework.util.StrictBitVector;
import iaik.security.ec.math.field.AbstractPrimeField;
import iaik.security.ec.math.field.PrimeFieldByPrimeFactory;
import iaik.security.ec.provider.ECCelerate;
import java.math.BigInteger;
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
    return null;
  }

  @Override
  public BigInteger convertToUnsigned(FieldElement value) {
    return null;
  }

  @Override
  public BigInteger convertToSigned(BigInteger asUnsigned) {
    return null;
  }

  @Override
  public byte[] serialize(FieldElement object) {
    return new byte[0];
  }

  @Override
  public byte[] serialize(List<FieldElement> objects) {
    return new byte[0];
  }

  @Override
  public FieldElement deserialize(byte[] bytes) {
    return null;
  }

  @Override
  public List<FieldElement> deserializeList(byte[] bytes) {
    return null;
  }
}
