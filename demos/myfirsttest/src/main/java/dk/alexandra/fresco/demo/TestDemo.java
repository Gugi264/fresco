package dk.alexandra.fresco.demo;

import dk.alexandra.fresco.demo.cli.CmdLineUtil;
import dk.alexandra.fresco.framework.Application;
import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.configuration.NetworkConfiguration;
import dk.alexandra.fresco.framework.sce.SecureComputationEngine;
import dk.alexandra.fresco.framework.sce.resources.ResourcePool;
import dk.alexandra.fresco.framework.value.SInt;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A simple demo computing the distance between two secret points.
 */
public class TestDemo implements Application<BigInteger, ProtocolBuilderNumeric> {

  private static Logger log = LoggerFactory.getLogger(TestDemo.class);

  private int myId;
  private int myX;

  /**
   * Construct a new TestDemo.
   * @param id The party id
   * @param x The x coordinate
   */
  public TestDemo(int id, int x) {
    this.myId = id;
    this.myX = x;
  }

  @Override
  public DRes<BigInteger> buildComputation(ProtocolBuilderNumeric producer) {
    return producer.par(par -> {
      // Input points
      Numeric numericIo = par.numeric();
      DRes<SInt> x1 = (myId == 1)
          ? numericIo.input(BigInteger.valueOf(myX), 1) : numericIo.input(null, 1);
      DRes<SInt> x2 = (myId == 2)
          ? numericIo.input(BigInteger.valueOf(myX), 2) : numericIo.input(null, 2);
      DRes<SInt> x3 = (myId == 3)
          ? numericIo.input(BigInteger.valueOf(myX), 3) : numericIo.input(null, 3);
      ArrayList<DRes<SInt>> inputs = new ArrayList<>(3);
      inputs.add(x1);
      inputs.add(x2);
      inputs.add(x3);
      return () -> inputs;
    }).seq((seq, inputs) -> {
      DRes<SInt> sum = null;
      DRes<SInt> low = null;
      DRes<SInt> high = null;
      for (DRes<SInt> input : inputs)
      {
        if (sum == null) {
          sum = input;
          low = input;
          high = input;
        }
        else {
          sum = seq.numeric().add(sum, input);
        }
      }
      long nr_inputs = inputs.size();
      sum = seq.advancedNumeric().div(sum, nr_inputs);
      return seq.numeric().open(sum);
    });
  }

  /**
   * Main method for DistanceDemo.
   * @param args Arguments for the application
   * @throws IOException In case of network problems
   */
  public static <ResourcePoolT extends ResourcePool> void main(String[] args) throws IOException {
    CmdLineUtil<ResourcePoolT, ProtocolBuilderNumeric> cmdUtil = new CmdLineUtil<>();
    int x = 0;
    cmdUtil.addOption(Option.builder("x").desc("The integer x coordinate of this party. "
        + "Note only party 1 and 2 should supply this input.").hasArg().build());
    CommandLine cmd = cmdUtil.parse(args);
    NetworkConfiguration networkConfiguration = cmdUtil.getNetworkConfiguration();

    if (networkConfiguration.getMyId() == 1 || networkConfiguration.getMyId() == 2 || networkConfiguration.getMyId() == 3) {
      if (!cmd.hasOption("x")) {
        cmdUtil.displayHelp();
        throw new IllegalArgumentException("Party 1 and 2 and 3 must submit input");
      } else {
        x = Integer.parseInt(cmd.getOptionValue("x"));
      }
    }

    TestDemo testDemo = new TestDemo(networkConfiguration.getMyId(), x);
    SecureComputationEngine<ResourcePoolT, ProtocolBuilderNumeric> sce = cmdUtil.getSce();
    ResourcePoolT resourcePool = cmdUtil.getResourcePool();
    BigInteger bigInteger = sce.runApplication(testDemo, resourcePool, cmdUtil.getNetwork());
    log.info("Average is: " + bigInteger);
    cmdUtil.closeNetwork();
    sce.shutdownSCE();

  }
}
