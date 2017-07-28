package dk.alexandra.fresco.lib.arithmetic;

import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.Computation;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThread;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadConfiguration;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadFactory;
import dk.alexandra.fresco.framework.builder.NumericBuilder;
import dk.alexandra.fresco.framework.builder.ProtocolBuilderNumeric.SequentialNumericBuilder;
import dk.alexandra.fresco.framework.network.ResourcePoolCreator;
import dk.alexandra.fresco.framework.sce.resources.ResourcePool;
import dk.alexandra.fresco.framework.value.SInt;
import dk.alexandra.fresco.lib.math.integer.ProductSIntList;
import dk.alexandra.fresco.lib.math.integer.SumSIntList;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Assert;

/**
 * Tests which ensures that the SecureComputationEngine's parallel and sequential evaluations of
 * application works.
 *
 * @author Kasper Damgaard
 */
public class ParallelAndSequenceTests {

  private static final Integer[] inputAsArray = {1, 2, 3, 4, 5, 6, 7, 8, 9};

  public static class TestSequentialEvaluation<ResourcePoolT extends ResourcePool> extends
      TestThreadFactory<ResourcePoolT, SequentialNumericBuilder> {

    @Override
    public TestThread<ResourcePoolT, SequentialNumericBuilder> next(
        TestThreadConfiguration<ResourcePoolT, SequentialNumericBuilder> conf) {
      return new TestThread<ResourcePoolT, SequentialNumericBuilder>() {
        @Override
        public void test() throws Exception {
          TestApplicationSum sumApp = new ParallelAndSequenceTests().new TestApplicationSum();
          TestApplicationMult multApp = new ParallelAndSequenceTests().new TestApplicationMult();

          ResourcePoolT resourcePool = ResourcePoolCreator.createResourcePool(conf.sceConf);
          BigInteger sum = secureComputationEngine.runApplication(sumApp, resourcePool);
          BigInteger mult = secureComputationEngine.runApplication(multApp, resourcePool);

          Assert
              .assertEquals(BigInteger.valueOf(1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9), sum);
          Assert
              .assertEquals(BigInteger.valueOf(1 * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9), mult);
        }
      };
    }
  }

  public static class TestParallelEvaluation<ResourcePoolT extends ResourcePool> extends
      TestThreadFactory<ResourcePoolT, SequentialNumericBuilder> {

    @Override
    public TestThread<ResourcePoolT, SequentialNumericBuilder> next(
        TestThreadConfiguration<ResourcePoolT, SequentialNumericBuilder> conf) {
      return new TestThread<ResourcePoolT, SequentialNumericBuilder>() {
        @Override
        public void test() throws Exception {
          TestApplicationSum sumApp = new ParallelAndSequenceTests().new TestApplicationSum();
          TestApplicationMult multApp = new ParallelAndSequenceTests().new TestApplicationMult();

          ResourcePoolT rp = ResourcePoolCreator.createResourcePool(conf.sceConf);
          BigInteger sum = secureComputationEngine
              .runApplication(sumApp, rp);
          BigInteger mult = secureComputationEngine.runApplication(multApp, rp);

          Assert
              .assertEquals(BigInteger.valueOf(1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9), sum);
          Assert
              .assertEquals(BigInteger.valueOf(1 * 2 * 3 * 4 * 5 * 6 * 7 * 8 * 9), mult);
        }
      };
    }
  }

  private class TestApplicationSum implements Application<BigInteger, SequentialNumericBuilder> {

    @Override
    public Computation<BigInteger> prepareApplication(
        SequentialNumericBuilder producer) {
      List<Computation<SInt>> input =
          Arrays.stream(inputAsArray)
              .map((integer) -> convertToSInt(integer, producer))
              .collect(Collectors.toList());
      Computation<SInt> result = producer.seq(new SumSIntList(input));
      return producer.numeric().open(result);
    }

  }

  private class TestApplicationMult implements Application<BigInteger, SequentialNumericBuilder> {

    @Override
    public Computation<BigInteger> prepareApplication(
        SequentialNumericBuilder producer) {
      Computation<SInt> result = producer.seq(new ProductSIntList(
          Arrays.stream(inputAsArray)
              .map((integer) -> convertToSInt(integer, producer))
              .collect(Collectors.toList())));
      return producer.numeric().open(result);
    }
  }

  private Computation<SInt> convertToSInt(int integer, SequentialNumericBuilder producer) {
    NumericBuilder numeric = producer.numeric();
    BigInteger value = BigInteger.valueOf(integer);
    return numeric.input(value, 1);
  }
}