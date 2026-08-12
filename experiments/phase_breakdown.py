from __future__ import annotations

import argparse
import math
import statistics
import time
from typing import List

from benchmark_common import build_environment


def timed_ms(function):
    start = time.perf_counter_ns()
    result = function()
    elapsed = (
        time.perf_counter_ns() - start
    ) / 1_000_000.0

    return result, elapsed


def stats(values: List[float]):
    mean = statistics.mean(values)

    sd = (
        statistics.stdev(values)
        if len(values) > 1
        else 0.0
    )

    ci = (
        1.96 * sd / math.sqrt(len(values))
        if len(values) > 1
        else 0.0
    )

    return mean, sd, min(values), max(values), ci


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--depth",
        type=int,
        default=3,
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=100,
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=10,
    )

    parser.add_argument(
        "--policy",
        choices=["local", "opa"],
        default="local",
    )

    args = parser.parse_args()

    env = build_environment(
        depth=args.depth,
        policy_mode=args.policy,
    )

    validator = env["validator"]
    policy = env["policy"]
    capability_service = env[
        "capability_service"
    ]
    ledger = env["ledger"]
    chain = env["chain"]
    request = env["request"]

    validation_samples = []
    policy_samples = []
    capability_samples = []
    ledger_samples = []

    def one_iteration(record: bool):
        validation, validation_ms = timed_ms(
            lambda: validator.validate(
                chain,
                request.request_time,
            )
        )

        if not validation.accepted:
            raise RuntimeError(
                "; ".join(validation.errors)
            )

        decision, policy_ms = timed_ms(
            lambda: policy.evaluate(
                request,
                validation.effective_scope,
            )
        )

        if not decision.allowed:
            raise RuntimeError(
                decision.reason
            )

        capability, capability_ms = timed_ms(
            lambda: capability_service.issue(
                subject_did=request.requester_did,
                chain=chain,
                effective_scope=(
                    validation.effective_scope
                ),
                capability_scope=[
                    decision.required_permission
                ],
                now=request.request_time,
            )
        )

        _, ledger_ms = timed_ms(
            lambda: ledger.anchor_authorization(
                chain,
                capability,
                request.request_time,
            )
        )

        if record:
            validation_samples.append(
                validation_ms
            )
            policy_samples.append(policy_ms)
            capability_samples.append(
                capability_ms
            )
            ledger_samples.append(ledger_ms)

    for _ in range(args.warmup):
        one_iteration(False)

    for _ in range(args.runs):
        one_iteration(True)

    print()
    print(
        f"CoDA phase breakdown "
        f"(depth={args.depth}, "
        f"policy={args.policy})"
    )

    print(
        "phase                    "
        "mean(ms)    sd(ms)   min(ms)   "
        "max(ms)  95%CI(ms)"
    )
    print("-" * 82)

    phases = [
        (
            "CoD validation",
            validation_samples,
        ),
        (
            "Policy evaluation",
            policy_samples,
        ),
        (
            "Capability issuance",
            capability_samples,
        ),
        (
            "Ledger anchoring",
            ledger_samples,
        ),
    ]

    for name, samples in phases:
        mean, sd, minimum, maximum, ci = (
            stats(samples)
        )

        print(
            f"{name:<24}"
            f"{mean:>9.3f}"
            f"{sd:>10.3f}"
            f"{minimum:>10.3f}"
            f"{maximum:>10.3f}"
            f"{ci:>11.3f}"
        )

    print()
    print(
        "Ledger anchoring here uses "
        "MemoryCommitmentLedger."
    )
    print(
        "It is not an IOTA ledger measurement."
    )


if __name__ == "__main__":
    main()
