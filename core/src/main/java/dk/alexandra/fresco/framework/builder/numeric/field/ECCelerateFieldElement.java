package dk.alexandra.fresco.framework.builder.numeric.field;

import iaik.security.ec.math.field.AbstractPrimeField;
import iaik.security.ec.math.field.PrimeFieldByPrimeFactory;
import iaik.security.ec.math.field.PrimeFieldElement;
import java.math.BigInteger;

public class ECCelerateFieldElement implements FieldElement{

  private AbstractPrimeField primeField;
  private PrimeFieldElement element;

  private ECCelerateFieldElement(PrimeFieldElement value, AbstractPrimeField field)
  {
    System.out.println("new ecc field element");
    this.primeField = field;
    this.element = value;
  }

  static FieldElement create(BigInteger value, AbstractPrimeField field) {
    return create(field.newElement(value), field);
  }

  static FieldElement create(long value, AbstractPrimeField field) {
    return create(BigInteger.valueOf(value), field);
  }
  static FieldElement create(PrimeFieldElement element, AbstractPrimeField field) {
    return new ECCelerateFieldElement(element, field);
  }

  @Override
  public FieldElement subtract(FieldElement other) {
    PrimeFieldElement other_element = ((ECCelerateFieldElement) other).getElement();
    return create(this.element.subtractOutOfPlace(other_element), this.primeField);
  }

  @Override
  public FieldElement negate() {
    return create(this.element.negateOutOfPlace(), this.primeField);
  }

  @Override
  public FieldElement multiply(FieldElement other) {
    PrimeFieldElement other_element = ((ECCelerateFieldElement) other).getElement();
    return create(this.element.multiplyOutOfPlace(other_element), this.primeField);
  }

  @Override
  public FieldElement sqrt() {
    return create(this.element.squareOutOfPlace(), this.primeField);
  }

  @Override
  public FieldElement modInverse() {
    System.out.println("MOnd inverse not implemented");
    return null;
  }

  @Override
  public FieldElement add(FieldElement other) {
    PrimeFieldElement other_element = ((ECCelerateFieldElement) other).getElement();
    return create(this.element.addOutOfPlace(other_element), this.primeField);
  }

  public PrimeFieldElement getElement() {
    return element;
  }

  static BigInteger extractValue(FieldElement element) {
    return ((ECCelerateFieldElement) element).element.toBigInteger();
  }
}
