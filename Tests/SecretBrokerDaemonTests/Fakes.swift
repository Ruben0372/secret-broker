import SecretBrokerCore

/// Fabricated audit tokens. No kernel token is ever obtained in tests: the
/// value is arbitrary and only its presence is meaningful to the foundations.
enum FakeAuditToken {
    static let valid = AuditToken(opaqueValue: 0x0000_0000_000A_11CE)
}
