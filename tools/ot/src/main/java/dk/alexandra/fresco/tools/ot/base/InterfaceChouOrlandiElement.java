package dk.alexandra.fresco.tools.ot.base;

import java.math.BigInteger;

public interface InterfaceChouOrlandiElement {

  /**
   * @return the Naor-Pinkas Element as a byte[]
   */
  byte[] toByteArray();

  /**
   * Performs the group operation
   * @param other
   * @return
   */
  InterfaceChouOrlandiElement groupOp(InterfaceChouOrlandiElement other);

  /**
   * Creates the inverse of the Naor-Pinkas Element
   * @return
   */
  InterfaceChouOrlandiElement inverse();


  /**
   * Performs the group operation n-times
   * @param n
   * @return
   */
  InterfaceChouOrlandiElement exponentiation(BigInteger n);

}
