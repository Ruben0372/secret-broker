import SecretBrokerContracts
import SecretBrokerCore
import Testing

/// Records how many operations were inside the critical section at once.
/// An actor rather than a plain counter, so the observation itself is not the
/// race being measured.
actor ConcurrencyWitness {
    private(set) var active = 0
    private(set) var peak = 0
    private(set) var completed = 0

    func enter() {
        active += 1
        peak = max(peak, active)
    }

    func leave() {
        active -= 1
        completed += 1
    }
}

@Suite("Serialized dispatch")
struct SerializedDispatchTests {
    static func allowingVerifier() -> PolicyCallerVerifier {
        PolicyCallerVerifier(policy: CallerVerificationTests.policy)
    }

    @Test("Concurrent dispatches never overlap")
    func dispatchesDoNotOverlap() async {
        let witness = ConcurrencyWitness()
        let dispatcher = SerializedDispatcher(verifier: Self.allowingVerifier())
        let caller = CallerVerificationTests.validCaller()

        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<16 {
                group.addTask {
                    _ = await dispatcher.dispatch(.availability, from: caller) {
                        await witness.enter()
                        // Yield repeatedly: a reentrant actor would interleave
                        // here, which is exactly what must not happen.
                        for _ in 0..<8 { await Task.yield() }
                        await witness.leave()
                        return .availabilityConfirmed
                    }
                }
            }
        }

        let peak = await witness.peak
        let completed = await witness.completed
        #expect(peak == 1, "dispatch overlapped: peak concurrency was \(peak)")
        #expect(completed == 16, "expected all 16 dispatches to complete, got \(completed)")
    }

    /// Non-vacuity control for the two peak == 1 assertions.
    ///
    /// Those assertions only mean something if the same workload would overlap
    /// without the dispatcher. Evidence held outside the repository proves
    /// nothing about a later change, so the control runs here: identical shape,
    /// identical yields, no lock.
    ///
    /// Scheduling is not guaranteed, so a single run could serialize by luck.
    /// It retries and fails only if every attempt serialized, which would mean
    /// the workload cannot demonstrate overlap and the strict assertions above
    /// are proving nothing.
    @Test("Control: the identical workload without the dispatcher does overlap")
    func unlockedWorkloadOverlaps() async {
        var bestPeak = 0

        for _ in 0..<5 {
            let witness = ConcurrencyWitness()
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<16 {
                    group.addTask {
                        await witness.enter()
                        for _ in 0..<8 { await Task.yield() }
                        await witness.leave()
                    }
                }
            }
            bestPeak = max(bestPeak, await witness.peak)
            if bestPeak >= 2 { break }
        }

        #expect(
            bestPeak >= 2,
            """
            the unlocked workload never overlapped across five attempts, peak \(bestPeak). \
            The serialization assertions cannot be trusted while this control cannot \
            demonstrate overlap: peak == 1 would then be a property of the workload, not of \
            the dispatcher.
            """
        )
    }

    @Test("Serialization holds across suspension inside the operation")
    func serializationSurvivesSuspension() async {
        let witness = ConcurrencyWitness()
        let dispatcher = SerializedDispatcher(verifier: Self.allowingVerifier())
        let caller = CallerVerificationTests.validCaller()

        await withTaskGroup(of: Void.self) { group in
            for index in 0..<8 {
                group.addTask {
                    _ = await dispatcher.dispatch(.availability, from: caller) {
                        await witness.enter()
                        // Uneven suspension lengths, so a queue that only looks
                        // serial under uniform timing is exposed.
                        for _ in 0..<(index * 3 + 1) { await Task.yield() }
                        await witness.leave()
                        return .availabilityConfirmed
                    }
                }
            }
        }

        let peak = await witness.peak
        #expect(peak == 1, "dispatch overlapped across suspension: peak was \(peak)")
    }

    @Test("A denied caller never reaches the operation body")
    func deniedCallerNeverRunsWork() async {
        let witness = ConcurrencyWitness()
        let dispatcher = SerializedDispatcher(verifier: Self.allowingVerifier())
        var caller = CallerVerificationTests.validCaller()
        caller.auditToken = nil

        let outcome = await dispatcher.dispatch(.availability, from: caller) {
            await witness.enter()
            await witness.leave()
            return .availabilityConfirmed
        }

        #expect(outcome == .denied(.missingAuditToken))
        let completed = await witness.completed
        #expect(completed == 0, "the operation body ran for a denied caller")
    }

    @Test("An allowed caller reaches the operation and gets its result class")
    func allowedCallerRunsWork() async {
        let dispatcher = SerializedDispatcher(verifier: Self.allowingVerifier())
        let outcome = await dispatcher.dispatch(
            .availability,
            from: CallerVerificationTests.validCaller()
        ) {
            .availabilityConfirmed
        }
        #expect(outcome == .completed(.availabilityConfirmed))
    }

    @Test("Production dispatch refuses every call, so the boundary is closed by default")
    func productionDispatchRefusesEverything() async {
        let witness = ConcurrencyWitness()
        let dispatcher = SerializedDispatcher(verifier: ProductionCallerVerifier())

        for _ in 0..<4 {
            let outcome = await dispatcher.dispatch(
                .availability,
                from: CallerVerificationTests.validCaller()
            ) {
                await witness.enter()
                await witness.leave()
                return .availabilityConfirmed
            }
            #expect(outcome == .denied(.productionVerificationUnavailable))
        }
        let completed = await witness.completed
        #expect(completed == 0, "production mode executed an operation body")
    }
}
