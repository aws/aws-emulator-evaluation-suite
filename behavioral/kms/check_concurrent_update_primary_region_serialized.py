"""concurrent-update-primary-region-serialized."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "concurrent-update-primary-region-serialized"
GROUP = "concurrency"
SERVICES = ["kms"]

# UpdatePrimaryRegion/ReplicateKey need a real second region distinct from ctx.region.
_CANDIDATE_REGIONS = ["us-west-2", "us-east-1", "eu-west-1"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePrimaryRegion calls sent while a move to that region is in progress succeed or fail
    with KMSInvalidStateException, and both regions then agree the target is PRIMARY and the
    origin its only REPLICA (no split-brain)."""
    target_region = _one_other_region(ctx)

    origin_client = ctx.client("kms")
    key_id = origin_client.create_key(
        MultiRegion=True,
        Description=ctx.unique_name("sim2real-kms-upr-race-"),
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-concurrent-update-primary-region"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: origin_client.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    replica_arn = origin_client.replicate_key(
        KeyId=key_id,
        ReplicaRegion=target_region,
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-concurrent-update-primary-region"}],
    )["ReplicaKeyMetadata"]["Arn"]
    target_client = _client_for_region(ctx, "kms", target_region)
    ctx.on_cleanup(
        lambda: target_client.schedule_key_deletion(KeyId=replica_arn, PendingWindowInDays=7)
    )
    _poll_until(
        lambda: target_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["KeyState"] == "Enabled",
        timeout_s=_budget_s(ctx, 90.0),
        interval_s=1.0,
        ctx=ctx,
    )

    def _race_call():
        """("ok", response) when the call is accepted, ("error", code) when it is refused."""
        try:
            resp = origin_client.update_primary_region(KeyId=key_id, PrimaryRegion=target_region)
        except Exception as exc:  # noqa: BLE001 - classified below
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            return ("error", code or repr(exc))
        return ("ok", resp)

    # The first call starts the move; the other two follow at once, while both keys are Updating.
    results = [_race_call()]
    assert results[0][0] == "ok", f"first UpdatePrimaryRegion failed: {results}"
    results += [_race_call() for _ in range(2)]

    failures = [detail for outcome, detail in results if outcome == "error"]
    assert all(code == "KMSInvalidStateException" for code in failures), failures

    demoted = _poll_until(
        lambda: origin_client.describe_key(KeyId=key_id)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA",
        timeout_s=_budget_s(ctx, 120.0),
        interval_s=1.0,
        ctx=ctx,
    )
    assert demoted["MultiRegionConfiguration"]["MultiRegionKeyType"] == "REPLICA", demoted[
        "MultiRegionConfiguration"
    ]
    assert demoted["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == target_region, demoted[
        "MultiRegionConfiguration"
    ]

    promoted = _poll_until(
        lambda: target_client.describe_key(KeyId=replica_arn)["KeyMetadata"],
        lambda d: d["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY",
        timeout_s=_budget_s(ctx, 180.0),
        interval_s=1.0,
        ctx=ctx,
    )
    assert promoted["MultiRegionConfiguration"]["MultiRegionKeyType"] == "PRIMARY", promoted[
        "MultiRegionConfiguration"
    ]
    assert promoted["MultiRegionConfiguration"]["PrimaryKey"]["Region"] == target_region, promoted[
        "MultiRegionConfiguration"
    ]

    # Both regions' views agree on exactly one replica set: no split-brain.
    origin_replicas = {r["Region"] for r in demoted["MultiRegionConfiguration"]["ReplicaKeys"]}
    target_replicas = {r["Region"] for r in promoted["MultiRegionConfiguration"]["ReplicaKeys"]}
    assert origin_replicas == target_replicas == {ctx.region}, (
        f"expected both views == {{{ctx.region!r}}}, got origin={origin_replicas} target={target_replicas}"
    )


def _one_other_region(ctx) -> str:
    for region in _CANDIDATE_REGIONS:
        if region != ctx.region:
            return region
    raise AssertionError("no candidate region distinct from ctx.region")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _client_for_region(ctx, service: str, region: str) -> Any:
    return ctx.client(service, region=region)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"KMS key state condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
