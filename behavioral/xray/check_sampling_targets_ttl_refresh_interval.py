"""sampling-targets-ttl-refresh-interval."""
from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from behavioral_harness import tags

CHECK = "sampling-targets-ttl-refresh-interval"
GROUP = "visibility-timeout-ttl"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSamplingTargets returns a ReservoirQuotaTTL at most 300 s after the call, and a later
    call returns a strictly later TTL, so a client knows when to refresh its quota."""
    xray = ctx.client("xray")
    name = ctx.unique_name("sim2real-xray-ttl-")
    client_id = os.urandom(12).hex()

    xray.create_sampling_rule(
        SamplingRule={
            "RuleName": name,
            "ResourceARN": "*",
            "Priority": 5000,
            "FixedRate": 0.1,
            "ReservoirSize": 2,
            "ServiceName": name,
            "ServiceType": "*",
            "Host": "*",
            "HTTPMethod": "*",
            "URLPath": "*",
            "Version": 1,
        }
    )
    ctx.on_cleanup(lambda: xray.delete_sampling_rule(RuleName=name))

    call1_time, target1 = _get_target_with_retry(
        ctx, name, client_id, request_count=5, sampled_count=2, timeout_s=90.0,
    )
    ttl1 = target1["ReservoirQuotaTTL"]
    if ttl1.tzinfo is None:
        ttl1 = ttl1.replace(tzinfo=timezone.utc)

    assert ttl1 > call1_time, (
        f"ReservoirQuotaTTL {ttl1} must be in the future relative to the call at {call1_time}"
    )
    window_s = (ttl1 - call1_time).total_seconds()
    assert 0 < window_s <= 300, (
        f"ReservoirQuotaTTL window is {window_s}s, expected a short bounded refresh "
        f"window (<=300s), not a far-future/permanent value"
    )

    # Poll: a later call must yield a strictly later TTL, confirming the target is
    # refreshed rather than being a fixed value the client could cache indefinitely.
    deadline = time.monotonic() + 90.0
    ttl2 = None
    while time.monotonic() < deadline:
        call2_time = datetime.now(timezone.utc)
        target2 = _get_target(
            ctx, name, client_id, call2_time.timestamp(), request_count=5, sampled_count=2
        )
        if target2 is None or target2.get("ReservoirQuotaTTL") is None:
            time.sleep(3.0)
            continue
        candidate = target2["ReservoirQuotaTTL"]
        if candidate.tzinfo is None:
            candidate = candidate.replace(tzinfo=timezone.utc)
        if candidate > ttl1:
            ttl2 = candidate
            break
        time.sleep(3.0)

    assert ttl2 is not None, f"ReservoirQuotaTTL never advanced past the first value {ttl1}"


def _get_target(ctx, rule_name, client_id, ts, request_count, sampled_count):
    xray = ctx.client("xray")
    resp = xray.get_sampling_targets(
        SamplingStatisticsDocuments=[
            {
                "RuleName": rule_name,
                "ClientID": client_id,
                "Timestamp": ts,
                "RequestCount": request_count,
                "SampledCount": sampled_count,
                "BorrowCount": 0,
            }
        ]
    )
    by_name = {t["RuleName"]: t for t in resp.get("SamplingTargetDocuments", [])}
    return by_name.get(rule_name)


def _get_target_with_retry(ctx, rule_name, client_id, request_count, sampled_count, timeout_s):
    """Retries GetSamplingTargets until the just-created rule is recognized AND has a
    ReservoirQuotaTTL populated -- both the rule's propagation and the TTL field itself
    (an optional field on SamplingTargetDocument) can lag a few seconds/polls behind
    the first statistics submission."""
    deadline = time.monotonic() + timeout_s
    last_target = None
    while True:
        call_time = datetime.now(timezone.utc)
        target = _get_target(ctx, rule_name, client_id, call_time.timestamp(), request_count, sampled_count)
        if target is not None:
            last_target = target
            if target.get("ReservoirQuotaTTL") is not None:
                return call_time, target
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no target with a populated ReservoirQuotaTTL for rule {rule_name!r} "
                f"within {timeout_s}s (last target seen: {last_target!r})"
            )
        time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

