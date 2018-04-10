package dk.alexandra.fresco.suite.spdz.gates.batched;

import dk.alexandra.fresco.framework.DRes;
import dk.alexandra.fresco.framework.builder.numeric.Numeric;
import dk.alexandra.fresco.framework.builder.numeric.ProtocolBuilderNumeric;
import dk.alexandra.fresco.framework.value.SInt;
import dk.alexandra.fresco.suite.spdz.SpdzRandomBitProtocol;
import dk.alexandra.fresco.suite.spdz.datatypes.SpdzSInt;
import dk.alexandra.fresco.suite.spdz.gates.SpdzAddProtocolKnownLeft;
import dk.alexandra.fresco.suite.spdz.gates.SpdzKnownSIntProtocol;
import dk.alexandra.fresco.suite.spdz.gates.SpdzMultProtocolKnownLeft;
import dk.alexandra.fresco.suite.spdz.gates.SpdzOutputSingleProtocol;
import dk.alexandra.fresco.suite.spdz.gates.SpdzOutputToAllProtocol;
import dk.alexandra.fresco.suite.spdz.gates.SpdzRandomProtocol;
import dk.alexandra.fresco.suite.spdz.gates.SpdzSubtractProtocol;
import dk.alexandra.fresco.suite.spdz.gates.SpdzSubtractProtocolKnownLeft;
import dk.alexandra.fresco.suite.spdz.gates.SpdzSubtractProtocolKnownRight;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class BatchedNumeric implements Numeric {

  private final ProtocolBuilderNumeric protocolBuilder;
  private SpdzBatchedMultiplication multiplications;
  private Map<Integer, SpdzBatchedInputComputation> inputs = new HashMap<>();

  public BatchedNumeric(ProtocolBuilderNumeric protocolBuilder) {
    this.protocolBuilder = protocolBuilder;
  }

  @Override
  public DRes<SInt> add(DRes<SInt> a, DRes<SInt> b) {
    return () -> SpdzSInt.toSpdzSInt(a).add(SpdzSInt.toSpdzSInt(b));
  }

  @Override
  public DRes<SInt> add(BigInteger a, DRes<SInt> b) {
    SpdzAddProtocolKnownLeft spdzAddProtocolKnownLeft = new SpdzAddProtocolKnownLeft(a, b);
    return protocolBuilder.append(spdzAddProtocolKnownLeft);
  }

  @Override
  public DRes<SInt> sub(DRes<SInt> a, DRes<SInt> b) {
    SpdzSubtractProtocol spdzSubtractProtocol = new SpdzSubtractProtocol(a, b);
    return protocolBuilder.append(spdzSubtractProtocol);
  }

  @Override
  public DRes<SInt> sub(BigInteger a, DRes<SInt> b) {
    SpdzSubtractProtocolKnownLeft spdzSubtractProtocolKnownLeft =
        new SpdzSubtractProtocolKnownLeft(a, b);
    return protocolBuilder.append(spdzSubtractProtocolKnownLeft);
  }

  @Override
  public DRes<SInt> sub(DRes<SInt> a, BigInteger b) {
    SpdzSubtractProtocolKnownRight spdzSubtractProtocolKnownRight =
        new SpdzSubtractProtocolKnownRight(a, b);
    return protocolBuilder.append(spdzSubtractProtocolKnownRight);
  }

  @Override
  public DRes<SInt> mult(DRes<SInt> a, DRes<SInt> b) {
    if (multiplications == null) {
      multiplications = new SpdzBatchedMultiplication();
      protocolBuilder.append(multiplications);
    }
    return multiplications.append(a, b);
  }

  @Override
  public DRes<SInt> mult(BigInteger a, DRes<SInt> b) {
    SpdzMultProtocolKnownLeft spdzMultProtocol4 = new SpdzMultProtocolKnownLeft(a, b);
    return protocolBuilder.append(spdzMultProtocol4);
  }

  @Override
  public DRes<SInt> randomBit() {
    return protocolBuilder.append(new SpdzRandomBitProtocol());
  }

  @Override
  public DRes<SInt> randomElement() {
    return protocolBuilder.append(new SpdzRandomProtocol());
  }

  @Override
  public DRes<SInt> known(BigInteger value) {
    return protocolBuilder.append(new SpdzKnownSIntProtocol(value));
  }

  @Override
  public DRes<SInt> input(BigInteger value, int inputParty) {
    System.out.println("here?");
    if (!inputs.containsKey(inputParty)) {
      SpdzBatchedInputComputation input = new SpdzBatchedInputComputation(
          inputParty, protocolBuilder.getBasicNumericContext().getNoOfParties());
      inputs.put(inputParty, input);
      protocolBuilder.seq(input);
    }
    return inputs.get(inputParty).append(value);
  }

  @Override
  public DRes<BigInteger> open(DRes<SInt> secretShare) {
    SpdzOutputToAllProtocol openProtocol = new SpdzOutputToAllProtocol(secretShare);
    return protocolBuilder.append(openProtocol);
  }

  @Override
  public DRes<BigInteger> open(DRes<SInt> secretShare, int outputParty) {
    SpdzOutputSingleProtocol openProtocol = new SpdzOutputSingleProtocol(secretShare,
        outputParty);
    return protocolBuilder.append(openProtocol);
  }

}