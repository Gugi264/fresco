package dk.alexandra.fresco.lib.common.math.integer.division;

import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThread;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadFactory;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.sce.resources.ResourcePool;
import dk.alexandra.fresco.framework.util.Pair;
import dk.alexandra.fresco.framework.value.SInt;
import dk.alexandra.fresco.lib.common.math.AdvancedNumeric;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import org.hamcrest.core.Is;
import org.junit.Assert;

/**
 * Generic test of the division computations.
 * <p>
 * Should be reusable for any protocol suite supporting a {@link ProtocolBuilderNumeric}.
 * </p>
 */
public class DivisionTests {

  /**
   * Creates a new division application that will compute both division and remainder with of a
   * given dividend with a known divisor.
   *
   * @param dividend the number to divide
   * @param divisor the divisor
   * @return an application do the given division
   */
  private static Application<Pair<BigInteger, BigInteger>, ProtocolBuilderNumeric>
      createDivideApplication(BigInteger dividend, BigInteger divisor) {
    return (builder) -> {
      Numeric numeric = builder.numeric();
      DRes<SInt> input1 = numeric.input(dividend, 1);
      DRes<SInt> division = AdvancedNumeric.using(builder).div(input1, divisor);
      DRes<SInt> remainder = builder.seq(new KnownDivisorRemainder(input1, divisor));
      DRes<BigInteger> output1 = numeric.open(division);
      DRes<BigInteger> output2 = numeric.open(remainder);
      return () -> new Pair<>(output1.out(), output2.out());
    };
  }

  /**
   * Tests division and remainder computation with known divisor (as implemented in
   * {@link KnownDivisor} and {@link KnownDivisorRemainder}).
   */
  public static class TestKnownDivisorDivision<ResourcePoolT extends ResourcePool>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {

      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {
        private final BigInteger[] openDividends = new BigInteger[] { new BigInteger("1234567"),
            BigInteger.valueOf(1230121230), BigInteger.valueOf(313222110),
            BigInteger.valueOf(5111215), BigInteger.valueOf(6537) };
        private final long openDivisor = 1110;
        private final int length = openDividends.length;

        @Override
        public void test() throws Exception {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app = (builder) -> {
            List<DRes<BigInteger>> results = new ArrayList<>(length);
            Numeric numericBuilder = builder.numeric();
            for (BigInteger value : openDividends) {
              DRes<SInt> dividend = numericBuilder.input(value, 1);
              DRes<SInt> division = AdvancedNumeric.using(builder).div(dividend, openDivisor);
              results.add(builder.numeric().open(division));
            }
            return () -> results.stream().map(DRes::out).collect(Collectors.toList());
          };
          List<BigInteger> results = runApplication(app);
          for (int i = 0; i < length; i++) {
            BigInteger actual = results.get(i);
            BigInteger expected = openDividends[i].divide(BigInteger.valueOf(openDivisor));
            boolean isCorrect = expected.equals(actual);
            Assert.assertTrue(isCorrect);
          }
        }
      };
    }

  }

  /**
   * Tests division and remainder computation with a large known divisor (as implemented in
   * {@link KnownDivisor} and {@link KnownDivisorRemainder}).
   */
  public static class TestKnownDivisorLargeDivisor<ResourcePoolT extends ResourcePool>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {

      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {
        private final BigInteger dividend = new BigInteger("123978634193227335452345761");
        private final BigInteger divisor =
            new BigInteger("956190705763692428873556826371298300651325076835323217712");

        @Override
        public void test() throws Exception {
          Application<Pair<BigInteger, BigInteger>, ProtocolBuilderNumeric> app =
              DivisionTests.createDivideApplication(dividend, divisor);
          Pair<BigInteger, BigInteger> result = runApplication(app);
          BigInteger quotient = result.getFirst();
          BigInteger remainder = result.getSecond();
          Assert.assertThat(quotient, Is.is(dividend.divide(divisor)));
          Assert.assertThat(remainder, Is.is(dividend.mod(divisor)));
        }
      };
    }
  }

  /**
   * Tests division and remainder computation with a secret divisor.
   */
  public static class TestDivision<ResourcePoolT extends ResourcePool>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {

      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {
        private final BigInteger[] openDividends = new BigInteger[] { new BigInteger("1234567"),
            BigInteger.valueOf(1230121230), BigInteger.valueOf(313222110),
            BigInteger.valueOf(5111215), BigInteger.valueOf(6537) };
        private final long openDivisor = 1110;
        private final int length = openDividends.length;

        @Override
        public void test() throws Exception {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app = (builder) -> {
            List<DRes<BigInteger>> results = new ArrayList<>(length);
            Numeric numericBuilder = builder.numeric();
            DRes<SInt> divisor = numericBuilder.input(openDivisor, 1);
            for (BigInteger value : openDividends) {
              DRes<SInt> dividend = numericBuilder.input(value, 1);
              DRes<SInt> division = AdvancedNumeric.using(builder).div(dividend, divisor);
              results.add(builder.numeric().open(division));
            }
            return () -> results.stream().map(DRes::out).collect(Collectors.toList());
          };
          List<BigInteger> results = runApplication(app);
          for (int i = 0; i < length; i++) {
            BigInteger actual = results.get(i);
            BigInteger expected = openDividends[i].divide(BigInteger.valueOf(openDivisor));
            boolean isCorrect = expected.equals(actual);
            Assert.assertTrue(isCorrect);
          }
        }
      };
    }
  }
}
