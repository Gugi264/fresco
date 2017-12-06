package dk.alexandra.fresco.logging;

import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.ProtocolEvaluator;
import dk.alexandra.fresco.framework.TestThreadRunner;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThread;
import dk.alexandra.fresco.framework.TestThreadRunner.TestThreadFactory;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.configuration.NetworkConfiguration;
import dk.alexandra.fresco.framework.configuration.TestConfiguration;
import dk.alexandra.fresco.framework.network.KryoNetNetwork;
import dk.alexandra.fresco.framework.sce.SecureComputationEngine;
import dk.alexandra.fresco.framework.sce.SecureComputationEngineImpl;
import dk.alexandra.fresco.framework.sce.evaluator.BatchEvaluationStrategy;
import dk.alexandra.fresco.framework.sce.evaluator.BatchedProtocolEvaluator;
import dk.alexandra.fresco.framework.sce.evaluator.EvaluationStrategy;
import dk.alexandra.fresco.framework.sce.resources.ResourcePool;
import dk.alexandra.fresco.framework.util.Drbg;
import dk.alexandra.fresco.framework.util.HmacDrbg;
import dk.alexandra.fresco.framework.value.SInt;
import dk.alexandra.fresco.lib.math.integer.sqrt.SqrtTests;
import dk.alexandra.fresco.suite.dummy.arithmetic.DummyArithmeticProtocolSuite;
import dk.alexandra.fresco.suite.dummy.arithmetic.DummyArithmeticResourcePool;
import dk.alexandra.fresco.suite.dummy.arithmetic.DummyArithmeticResourcePoolImpl;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.hamcrest.core.Is;
import org.junit.Assert;
import org.junit.Test;

public class TestGenericLoggingDecorators {

  private final BigInteger mod 
    = new BigInteger("6703903964971298549787012499123814115273848577471136527425966013026501536706464354255445443244279389455058889493431223951165286470575994074291745908195329");

  @Test
  public void testPerformanceLoggerEnums(){
    Assert.assertThat(PerformanceLogger.Flag.valueOf("LOG_EVALUATOR"), Is.is(PerformanceLogger.Flag.LOG_EVALUATOR));
    Assert.assertThat(PerformanceLogger.Flag.valueOf("LOG_NETWORK"), Is.is(PerformanceLogger.Flag.LOG_NETWORK));
    Assert.assertThat(PerformanceLogger.Flag.valueOf("LOG_NATIVE_BATCH"), Is.is(PerformanceLogger.Flag.LOG_NATIVE_BATCH));
  }
  
  @Test
  public void testEvaluatorLoggingDecorator() throws Exception {
    TestThreadRunner.TestThreadFactory<DummyArithmeticResourcePool, ProtocolBuilderNumeric> f
        = new TestSquareRootStartApplication<>();

    EvaluationStrategy evalStrategy = EvaluationStrategy.SEQUENTIAL; 
    Map<Integer, NetworkConfiguration> netConf = getNetConf();
    Map<Integer, TestThreadRunner.TestThreadConfiguration<DummyArithmeticResourcePool, ProtocolBuilderNumeric>> conf =
        new HashMap<>();

    Map<Integer, ListLogger> pls = new HashMap<>();
    List<PerformanceLogger> decoratedLoggers = new ArrayList<>();
    for (int playerId : netConf.keySet()) {
      pls.put(playerId, new ListLogger());
      NetworkConfiguration partyNetConf = netConf.get(playerId);
      
      DummyArithmeticProtocolSuite ps = new DummyArithmeticProtocolSuite(mod, 200);
      BatchEvaluationStrategy<DummyArithmeticResourcePool> strat = evalStrategy.getStrategy();
      ProtocolEvaluator<DummyArithmeticResourcePool, ProtocolBuilderNumeric> evaluator 
          = new BatchedProtocolEvaluator<>(strat, ps);
      EvaluatorLoggingDecorator<DummyArithmeticResourcePool, ProtocolBuilderNumeric> decoratedEvaluator
          = new EvaluatorLoggingDecorator<>(evaluator);
      SecureComputationEngine<DummyArithmeticResourcePool, ProtocolBuilderNumeric> sce 
          = new SecureComputationEngineImpl<>(ps, decoratedEvaluator);
      decoratedLoggers.add(decoratedEvaluator);
      
      Drbg drbg = new HmacDrbg();
      TestThreadRunner.TestThreadConfiguration<DummyArithmeticResourcePool, ProtocolBuilderNumeric> ttc =
          new TestThreadRunner.TestThreadConfiguration<>(sce,
              () -> new DummyArithmeticResourcePoolImpl(playerId,
                  netConf.keySet().size(), drbg, mod),
              () -> {
                return new KryoNetNetwork(partyNetConf);
              });
      conf.put(playerId, ttc);
    }
    TestThreadRunner.run(f, conf);

    for (Integer pId : pls.keySet()) {
     
      decoratedLoggers.get(0).printToLog(pls.get(pId), pId);
      Map<String, Object> loggedValues = decoratedLoggers.get(0).getLoggedValues(pId);
      
      List<Long> runningTimes = (List<Long>)loggedValues.get(EvaluatorLoggingDecorator.SCE_RUNNINGTIMES);
      Assert.assertTrue(runningTimes.get(0) > 0);
      Assert.assertTrue(pls.get(pId).getData().get(0).contains("Running times for evaluations ==="));
      Assert.assertTrue(pls.get(pId).getData().get(1).contains("Application 1 took"));
    }
    
    for (Integer pId : pls.keySet()) {
      PerformanceLogger pl = decoratedLoggers.get(0);
      pl.reset();
      pl.printToLog(pls.get(pId), pId);
      Assert.assertTrue(((List)pl.getLoggedValues(pId).get(EvaluatorLoggingDecorator.SCE_RUNNINGTIMES)).size() == 0);
      Assert.assertTrue(pls.get(pId).getData().get(3).contains("No applications were run, or they have not completed yet."));
    }
  }  
  


  @Test
  public void testNetworkLoggingDecorator() throws Exception {
    
    TestThreadRunner.TestThreadFactory<DummyArithmeticResourcePool, ProtocolBuilderNumeric> f
        = new SqrtTests.TestSquareRoot<>();

    EvaluationStrategy evalStrategy = EvaluationStrategy.SEQUENTIAL; 
    Map<Integer, NetworkConfiguration> netConf = getNetConf();
    Map<Integer, TestThreadRunner.TestThreadConfiguration<DummyArithmeticResourcePool, ProtocolBuilderNumeric>> conf =
        new HashMap<>();

    Map<Integer, ListLogger> pls = new HashMap<>();
    List<PerformanceLogger> decoratedLoggers = new ArrayList<>();
    for (int playerId : netConf.keySet()) {
      pls.put(playerId, new ListLogger());
      NetworkConfiguration partyNetConf = netConf.get(playerId);
      
      DummyArithmeticProtocolSuite ps = new DummyArithmeticProtocolSuite(mod, 200);
      BatchEvaluationStrategy<DummyArithmeticResourcePool> strat = evalStrategy.getStrategy();
      ProtocolEvaluator<DummyArithmeticResourcePool, ProtocolBuilderNumeric> evaluator 
          = new BatchedProtocolEvaluator<>(strat, ps);
      SecureComputationEngine<DummyArithmeticResourcePool, ProtocolBuilderNumeric> sce 
          = new SecureComputationEngineImpl<>(ps, evaluator);
      
      Drbg drbg = new HmacDrbg();
      TestThreadRunner.TestThreadConfiguration<DummyArithmeticResourcePool, ProtocolBuilderNumeric> ttc =
          new TestThreadRunner.TestThreadConfiguration<>(sce,
              () -> new DummyArithmeticResourcePoolImpl(playerId,
                  netConf.keySet().size(), drbg, mod),
              () -> {
                NetworkLoggingDecorator network = new NetworkLoggingDecorator(new KryoNetNetwork(partyNetConf));
                decoratedLoggers.add(network);
                network.printToLog(pls.get(playerId), playerId);
                return network;
              });
      conf.put(playerId, ttc);
    }
    TestThreadRunner.run(f, conf);

    for (Integer pId : pls.keySet()) {
      Assert.assertTrue(pls.get(pId).getData().get(0).contains("Network logged - results ==="));
      Assert.assertTrue(pls.get(pId).getData().get(1).contains("Received data 0 times in total (including from ourselves)"));
      Assert.assertTrue(pls.get(pId).getData().get(2).contains("Total amount of bytes received: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(3).contains("Minimum amount of bytes received: 2147483647"));
      Assert.assertTrue(pls.get(pId).getData().get(4).contains("Maximum amount of bytes received: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(5).contains("Average amount of bytes received:"));

      decoratedLoggers.get(0).printToLog(pls.get(pId), pId);
      Map<String, Object> loggedValues = decoratedLoggers.get(0).getLoggedValues(pId);
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_TOTAL_BYTES), Is.is((long)396));
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_TOTAL_BATCHES), Is.is(6));
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_MAX_BYTES), Is.is(66));
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_MIN_BYTES), Is.is(66));
      Assert.assertThat(((Map<Integer, Integer>)loggedValues.get(NetworkLoggingDecorator.NETWORK_PARTY_BYTES)).get(1), Is.is(396));

      Assert.assertTrue(pls.get(pId).getData().get(7).contains("Received 396 bytes from party 1"));
      Assert.assertTrue(pls.get(pId).getData().get(8).contains("Received data 6 times in total (including from ourselves)"));
      Assert.assertTrue(pls.get(pId).getData().get(9).contains("Total amount of bytes received: 396"));
      Assert.assertTrue(pls.get(pId).getData().get(10).contains("Minimum amount of bytes received: 66"));
      Assert.assertTrue(pls.get(pId).getData().get(11).contains("Maximum amount of bytes received: 66"));
      Assert.assertTrue(pls.get(pId).getData().get(12).contains("Average amount of bytes received: 66.00"));
    }
    
    for (Integer pId : pls.keySet()) {
      PerformanceLogger pl = decoratedLoggers.get(0);
      pl.reset();
      pl.printToLog(pls.get(pId), pId);
    
      Map<String, Object> loggedValues = decoratedLoggers.get(0).getLoggedValues(pId);
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_TOTAL_BYTES), Is.is((long)0));
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_TOTAL_BATCHES), Is.is(0));
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_MAX_BYTES), Is.is(0));
      Assert.assertThat(loggedValues.get(NetworkLoggingDecorator.NETWORK_MIN_BYTES), Is.is(Integer.MAX_VALUE));
      Assert.assertThat(((Map<Integer, Integer>)loggedValues.get(NetworkLoggingDecorator.NETWORK_PARTY_BYTES)).size(), Is.is(0));      
      Assert.assertTrue(pls.get(pId).getData().get(14).contains("Received data 0 times in total (including from ourselves)"));
      Assert.assertTrue(pls.get(pId).getData().get(15).contains("Total amount of bytes received: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(16).contains("Minimum amount of bytes received: 2147483647"));
      Assert.assertTrue(pls.get(pId).getData().get(17).contains("Maximum amount of bytes received: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(18).contains("Average amount of bytes received:"));
    }
  }
  
  
  @Test
  public void testBatchEvaluationLoggingDecorator() throws Exception {
    
    TestThreadRunner.TestThreadFactory<DummyArithmeticResourcePool, ProtocolBuilderNumeric> f
        = new SqrtTests.TestSquareRoot<>();

    EvaluationStrategy evalStrategy = EvaluationStrategy.SEQUENTIAL; 

    Map<Integer, NetworkConfiguration> netConf = getNetConf();

    Map<Integer, TestThreadRunner.TestThreadConfiguration<DummyArithmeticResourcePool, ProtocolBuilderNumeric>> conf =
        new HashMap<>();

    Map<Integer, ListLogger> pls = new HashMap<>();
    List<PerformanceLogger> decoratedLoggers = new ArrayList<>();
    for (int playerId : netConf.keySet()) {
      pls.put(playerId, new ListLogger());
      NetworkConfiguration partyNetConf = netConf.get(playerId);
      
      DummyArithmeticProtocolSuite ps = new DummyArithmeticProtocolSuite(mod, 200);
      BatchEvaluationStrategy<DummyArithmeticResourcePool> strat = evalStrategy.getStrategy();
      BatchEvaluationLoggingDecorator<DummyArithmeticResourcePool> decoratedStrat =
          new BatchEvaluationLoggingDecorator<>(strat);
      decoratedLoggers.add(decoratedStrat);
      decoratedStrat.printToLog(pls.get(playerId), playerId);
      
      ProtocolEvaluator<DummyArithmeticResourcePool, ProtocolBuilderNumeric> evaluator 
          = new BatchedProtocolEvaluator<>(decoratedStrat, ps);
      SecureComputationEngine<DummyArithmeticResourcePool, ProtocolBuilderNumeric> sce 
          = new SecureComputationEngineImpl<>(ps, evaluator);
      
      Drbg drbg = new HmacDrbg();
      TestThreadRunner.TestThreadConfiguration<DummyArithmeticResourcePool, ProtocolBuilderNumeric> ttc =
          new TestThreadRunner.TestThreadConfiguration<>(sce,
              () -> new DummyArithmeticResourcePoolImpl(playerId,
                  netConf.keySet().size(), drbg, mod),
              () -> {
                return new KryoNetNetwork(partyNetConf);
              });
      conf.put(playerId, ttc);
    }
    TestThreadRunner.run(f, conf);

    for (Integer pId : pls.keySet()) {
      Assert.assertTrue(pls.get(pId).getData().get(0).contains("Native protocols per batch metrics ==="));
      Assert.assertTrue(pls.get(pId).getData().get(1).contains("Total amount of batches reached: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(2).contains("Total amount of native protocols evaluated: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(3).contains("minimum amount of native protocols evaluated in a single batch: 2147483647"));
      Assert.assertTrue(pls.get(pId).getData().get(4).contains("maximum amount of native protocols evaluated in a single batch: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(5).contains("Average amount of native protocols evaluated per batch"));
      
      decoratedLoggers.get(0).printToLog(pls.get(pId), pId);
      Map<String, Object> loggedValues = decoratedLoggers.get(0).getLoggedValues(pId);
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_COUNTER), Is.is(3496361));
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_NATIVE_PROTOCOLS), Is.is(17275821));
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_MIN_PROTOCOLS), Is.is(1));
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_MAX_PROTOCOLS), Is.is(520));
      Assert.assertTrue(pls.get(pId).getData().get(7).contains("Total amount of batches reached: 3496361"));
      Assert.assertTrue(pls.get(pId).getData().get(8).contains("Total amount of native protocols evaluated: 17275821"));
      Assert.assertTrue(pls.get(pId).getData().get(9).contains("minimum amount of native protocols evaluated in a single batch: 1"));
      Assert.assertTrue(pls.get(pId).getData().get(10).contains("maximum amount of native protocols evaluated in a single batch: 520"));
      Assert.assertTrue(pls.get(pId).getData().get(11).contains("Average amount of native protocols evaluated per batch: 4.94"));
    }
    
    for (Integer pId : pls.keySet()) {
      PerformanceLogger pl = decoratedLoggers.get(0);
      pl.reset();
      pl.printToLog(pls.get(pId), pId);
      Map<String, Object> loggedValues = decoratedLoggers.get(0).getLoggedValues(pId);
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_COUNTER), Is.is(0));
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_NATIVE_PROTOCOLS), Is.is(0));
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_MIN_PROTOCOLS), Is.is(Integer.MAX_VALUE));
      Assert.assertThat(loggedValues.get(BatchEvaluationLoggingDecorator.BATCH_MAX_PROTOCOLS), Is.is(0));

      Assert.assertTrue(pls.get(pId).getData().get(13).contains("Total amount of batches reached: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(14).contains("Total amount of native protocols evaluated: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(15).contains("minimum amount of native protocols evaluated in a single batch: 2147483647"));
      Assert.assertTrue(pls.get(pId).getData().get(16).contains("maximum amount of native protocols evaluated in a single batch: 0"));
      Assert.assertTrue(pls.get(pId).getData().get(17).contains("Average amount of native protocols evaluated per batch"));
    }
  }
  
  private Map<Integer, NetworkConfiguration> getNetConf() {
    int noOfParties = 2;
    List<Integer> ports = new ArrayList<>(noOfParties);
    for (int i = 1; i <= noOfParties; i++) {
      ports.add(9000 + i * (noOfParties - 1));
    }
    return TestConfiguration.getNetworkConfigurations(noOfParties, ports);
  }
  
  
  public static class TestSquareRootStartApplication<ResourcePoolT extends ResourcePool>
      extends TestThreadFactory<ResourcePoolT, ProtocolBuilderNumeric> {

    @Override
    public TestThread<ResourcePoolT, ProtocolBuilderNumeric> next() {
      
      return new TestThread<ResourcePoolT, ProtocolBuilderNumeric>() {

        private final int maxBitLength = 32;
        private final BigInteger[] x = new BigInteger[] {BigInteger.valueOf(1234),
            BigInteger.valueOf(12345), BigInteger.valueOf(123456), BigInteger.valueOf(1234567),
            BigInteger.valueOf(12345678), BigInteger.valueOf(123456789)};
        private final int n = x.length;

        @Override
        protected <OutputT> OutputT runApplication(Application<OutputT, ProtocolBuilderNumeric> app) {
          try {
            return conf.sce.startApplication(app, conf.getResourcePool(), conf.getNetwork()).get();
          } catch (Exception e) {
            e.printStackTrace();
          }
          return null;
        }

        @Override
        public void test() throws Exception {
          Application<List<BigInteger>, ProtocolBuilderNumeric> app = builder -> {
            Numeric numBuilder = builder.numeric();

            List<DRes<BigInteger>> results = new ArrayList<>(n);

            for (BigInteger input : x) {
              DRes<SInt> actualInput = numBuilder.input(input, 1);
              DRes<SInt> result = builder.advancedNumeric().sqrt(actualInput, maxBitLength);
              DRes<BigInteger> openResult = builder.numeric().open(result);
              results.add(openResult);
            }
            return () -> results.stream().map(DRes::out).collect(Collectors.toList());
          };

          List<BigInteger> results = runApplication(app);
          Assert.assertEquals(n, results.size());
          // We are not really interested in the result, only the running time
        }
      };
    }
  }

}