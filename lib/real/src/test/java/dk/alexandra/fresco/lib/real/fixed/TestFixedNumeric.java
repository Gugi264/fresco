package dk.alexandra.fresco.lib.real.fixed;

import dk.alexandra.fresco.framework.builder.numeric.BuilderFactoryNumeric;
import dk.alexandra.fresco.framework.builder.numeric.field.BigIntegerFieldDefinition;
import dk.alexandra.fresco.framework.util.ModulusFinder;
import dk.alexandra.fresco.lib.field.integer.BasicNumericContext;
import dk.alexandra.fresco.lib.real.RealNumericContext;
import dk.alexandra.fresco.suite.dummy.arithmetic.DummyArithmeticBuilderFactory;
import org.junit.Test;

public class TestFixedNumeric {

  private final BigIntegerFieldDefinition fieldDefinition = new BigIntegerFieldDefinition(
      ModulusFinder.findSuitableModulus(8));

  @Test
  public void testFixedNumericLegalPrecision() {
    BuilderFactoryNumeric bfn = new DummyArithmeticBuilderFactory(
        new BasicNumericContext(16, 1, 1, fieldDefinition, 0));
    new FixedNumeric(bfn.createSequential());
  }

  @Test(expected = NullPointerException.class)
  public void testFixedNumericNullBuilder() {
    new FixedNumeric(null);
  }
}
