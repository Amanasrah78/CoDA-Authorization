from __future__ import annotations

import argparse
import csv
import math
import statistics
import time
from pathlib import Path
from typing import Dict, List

from benchmark_common import build_environment


def measure_ms(function):
    start = time.perf_counter_ns()
    result = function()
    end = time.perf_counter_ns()

    elapsed_ms = (end - start) / 1_000_000.0

    return result, elapsed_ms


def summarize(values: List[float]) -> Dict[str, float]:
    if not values:
        raise ValueError("cannot summarize an empty sample")

    count = len(values)
    mean = statistics.mean(values)

    if count > 1:
        sd = statistics.stdev(values)
    else:
        sd = 0.0

    ci95 = (
        1.96 * sd / math.sqrt(count)
        if count > 1
        else 0.0
    )

    return {
        "runs": count,
        "mean_ms": mean,
        "sd_ms": sd,
        "min_ms": min(values),
        "max_ms": max(values),
        "ci95_ms": ci95,
    }


def benchmark_depth(
    depth: int,
    runs: int,
    warmup: int,
    policy_mode: str,
):
    env = build_environment(
        depth=depth,
        policy_mode=policy_mode,
    )

    service = env["service"]
    ledger = env["ledger"]
    request = env["request"]
    chain = env["chain"]

    # ---------------------------------------------------------
    # Warm-up
    #
    # Warm-up operations exercise both the online authorization
    # path and the post-authorization ledger path. These samples
    # are not included in reported measurements.
    # ---------------------------------------------------------
    for _ in range(warmup):
        outcome = service.authorize(
            request=request,
            chain=chain,
            anchor_to_ledger=False,
        )

        if not outcome.accepted:
            raise RuntimeError(
                f"warm-up authorization failed: "
                f"{outcome.reason}"
            )

        if outcome.capability is None:
            raise RuntimeError(
                "warm-up authorization produced no capability"
            )

        ledger.anchor_authorization(
            chain=chain,
            capability=outcome.capability,
            timestamp=request.request_time,
        )

    online_samples: List[float] = []
    ledger_samples: List[float] = []
    inclusive_samples: List[float] = []

    # ---------------------------------------------------------
    # Measurement
    #
    # For every trial:
    #
    #   T_online
    #       = CoD validation
    #       + request/context checks
    #       + policy evaluation
    #       + capability issuance
    #
    #   T_ledger
    #       = post-authorization ledger anchoring
    #
    #   T_inclusive
    #       = T_online + T_ledger
    #
    # Therefore T_inclusive >= T_online for every trial.
    # ---------------------------------------------------------
    for _ in range(runs):
        outcome, online_ms = measure_ms(
            lambda: service.authorize(
                request=request,
                chain=chain,
                anchor_to_ledger=False,
            )
        )

        if not outcome.accepted:
            raise RuntimeError(
                f"authorization failed: "
                f"{outcome.reason}"
            )

        if outcome.capability is None:
            raise RuntimeError(
                "successful authorization produced "
                "no capability"
            )

        _, ledger_ms = measure_ms(
            lambda: ledger.anchor_authorization(
                chain=chain,
                capability=outcome.capability,
                timestamp=request.request_time,
            )
        )

        inclusive_ms = online_ms + ledger_ms

        online_samples.append(online_ms)
        ledger_samples.append(ledger_ms)
        inclusive_samples.append(inclusive_ms)

    # Defensive check: the benchmark definition requires this.
    for online_ms, inclusive_ms in zip(
        online_samples,
        inclusive_samples,
    ):
        if inclusive_ms < online_ms:
            raise RuntimeError(
                "invalid measurement: ledger-inclusive "
                "latency is below online latency"
            )

    return {
        "online": summarize(online_samples),
        "ledger_anchoring": summarize(ledger_samples),
        "ledger_inclusive": summarize(
            inclusive_samples
        ),
    }


def print_summary(
    depth: int,
    category: str,
    stats: Dict[str, float],
):
    print(
        f"{depth:>5} "
        f"{category:<22} "
        f"{stats['mean_ms']:>9.3f} "
        f"{stats['sd_ms']:>9.3f} "
        f"{stats['min_ms']:>9.3f} "
        f"{stats['max_ms']:>9.3f} "
        f"{stats['ci95_ms']:>9.3f}"
    )


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Measure CoDA online authorization, "
            "post-authorization ledger anchoring, and "
            "ledger-inclusive realization."
        )
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
        "--depths",
        type=int,
        nargs="+",
        default=[1, 2, 3],
    )

    parser.add_argument(
        "--policy",
        choices=["local", "opa"],
        default="local",
    )

    parser.add_argument(
        "--output",
        default="results/authorization_latency.csv",
    )

    args = parser.parse_args()

    if args.runs < 1:
        raise SystemExit("--runs must be >= 1")

    if args.warmup < 0:
        raise SystemExit("--warmup must be >= 0")

    for depth in args.depths:
        if depth < 1:
            raise SystemExit(
                "all delegation depths must be >= 1"
            )

    Path(args.output).parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = []

    print()
    print(
        "depth category                 "
        "mean(ms)    sd(ms)   min(ms)   "
        "max(ms)  95%CI(ms)"
    )
    print("-" * 83)

    for depth in args.depths:
        result = benchmark_depth(
            depth=depth,
            runs=args.runs,
            warmup=args.warmup,
            policy_mode=args.policy,
        )

        for category in [
            "online",
            "ledger_anchoring",
            "ledger_inclusive",
        ]:
            category_stats = result[category]

            print_summary(
                depth,
                category,
                category_stats,
            )

            rows.append(
                {
                    "depth": depth,
                    "category": category,
                    "policy": args.policy,
                    **category_stats,
                }
            )

    with open(
        args.output,
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "depth",
                "category",
                "policy",
                "runs",
                "mean_ms",
                "sd_ms",
                "min_ms",
                "max_ms",
                "ci95_ms",
            ],
        )

        writer.writeheader()
        writer.writerows(rows)

    print()
    print(f"Results written to: {args.output}")

    print()
    print(
        "Measurement definitions:"
    )
    print(
        "  online            = authorization through "
        "capability issuance"
    )
    print(
        "  ledger_anchoring  = post-authorization "
        "commitment only"
    )
    print(
        "  ledger_inclusive  = online + ledger_anchoring"
    )

    print()
    print(
        "IMPORTANT: these are fresh measurements from "
        "the reconstructed reference implementation."
    )
    print(
        "The MemoryCommitmentLedger is not an IOTA "
        "ledger implementation."
    )
    print(
        "These values must not be represented as the "
        "manuscript's original measurements."
    )


if __name__ == "__main__":
    main()
