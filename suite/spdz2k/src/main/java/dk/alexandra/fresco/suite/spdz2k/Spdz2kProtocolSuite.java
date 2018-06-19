package dk.alexandra.fresco.suite.spdz2k;

import dk.alexandra.fresco.framework.builder.numeric.BuilderFactoryNumeric;
import dk.alexandra.fresco.framework.network.Network;
import dk.alexandra.fresco.lib.field.integer.BasicNumericContext;
import dk.alexandra.fresco.lib.real.RealNumericContext;
import dk.alexandra.fresco.suite.ProtocolSuiteNumeric;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUInt;
import dk.alexandra.fresco.suite.spdz2k.datatypes.CompUIntConverter;
import dk.alexandra.fresco.suite.spdz2k.datatypes.UInt;
import dk.alexandra.fresco.suite.spdz2k.protocols.computations.MacCheckComputationSpdz2k;
import dk.alexandra.fresco.suite.spdz2k.resource.Spdz2kResourcePool;
import dk.alexandra.fresco.suite.spdz2k.synchronization.Spdz2kRoundSynchronization;

/**
 * The SPDZ2k protocol suite. <p>This suite works with ring elements. Each ring element, represented
 * by {@link PlainT} is conceptually composed of two smaller ring elements, represented by {@link
 * HighT} and {@link LowT}, i.e., a most significant bit portion and a least significant bit
 * portion. The least-significant bit portion is used to store the actual value (or secret-share
 * thereof) we are computing on. The most-significant bit portion is required for security and is
 * used in the mac-check protocol implemented in {@link MacCheckComputationSpdz2k}.</p>
 *
 * @param <HighT> type representing most significant bit portion of open values
 * @param <LowT> type representing least significant bit portion of open values
 * @param <PlainT> the type representing open values
 */
public abstract class Spdz2kProtocolSuite<
    HighT extends UInt<HighT>,
    LowT extends UInt<LowT>,
    PlainT extends CompUInt<HighT, LowT, PlainT>>
    implements ProtocolSuiteNumeric<Spdz2kResourcePool<PlainT>> {

  private static final int DEFAULT_FIXED_POINT_PRECISION = 16;

  private final CompUIntConverter<HighT, LowT, PlainT> converter;
  private final boolean useBooleanMode;
  private final int fixedPointPrecision;

  /**
   * Constructs new {@link Spdz2kProtocolSuite}.
   *
   * @param converter helper which allows converting {@link HighT}, and {@link LowT} instances to
   * {@link PlainT}. This is necessary for the mac-check protocol where we perform arithmetic
   * between these different types.
   * @param useBooleanMode flag for switching to boolean shares for logical operations
   */
  Spdz2kProtocolSuite(CompUIntConverter<HighT, LowT, PlainT> converter,
      boolean useBooleanMode,
      int fixedPointPrecision) {
    this.converter = converter;
    this.useBooleanMode = useBooleanMode;
    this.fixedPointPrecision = fixedPointPrecision;
  }

  Spdz2kProtocolSuite(CompUIntConverter<HighT, LowT, PlainT> converter, int fixedPointPrecision) {
    this(converter, false, fixedPointPrecision);
  }

  Spdz2kProtocolSuite(CompUIntConverter<HighT, LowT, PlainT> converter, boolean useBooleanMode) {
    this(converter, useBooleanMode, DEFAULT_FIXED_POINT_PRECISION);
  }

  Spdz2kProtocolSuite(CompUIntConverter<HighT, LowT, PlainT> converter) {
    this(converter, false, DEFAULT_FIXED_POINT_PRECISION);
  }

  @Override
  public BuilderFactoryNumeric init(Spdz2kResourcePool<PlainT> resourcePool, Network network) {
    return new Spdz2kBuilder<>(resourcePool.getFactory(),
        createBasicNumericContext(resourcePool),
        createRealNumericContext(),
        useBooleanMode);
  }

  @Override
  public RoundSynchronization<Spdz2kResourcePool<PlainT>> createRoundSynchronization() {
    return new Spdz2kRoundSynchronization<>(this, converter);
  }

  public BasicNumericContext createBasicNumericContext(Spdz2kResourcePool<PlainT> resourcePool) {
    return new BasicNumericContext(
        resourcePool.getMaxBitLength(), resourcePool.getModulus(), resourcePool.getMyId(),
        resourcePool.getNoOfParties());
  }

  public RealNumericContext createRealNumericContext() {
    return new RealNumericContext(fixedPointPrecision);
  }

}
