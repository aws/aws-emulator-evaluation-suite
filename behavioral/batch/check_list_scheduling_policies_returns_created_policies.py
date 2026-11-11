"""list-scheduling-policies-returns-created-policies."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-scheduling-policies-returns-created-policies"
GROUP = "state-machine"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSchedulingPolicies enumerates all created scheduling policies and omits them
    once deleted."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-schedpol-")
    created = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "computeReservation": 0,
            "shareDecaySeconds": 0,
            # Real AWS Batch rejects shareIdentifier values containing a hyphen
            # ("ShareIdentifier name should ..." only alphanumeric/underscore); use an
            # alphanumeric identifier instead.
            "shareDistribution": [{"shareIdentifier": "teamA", "weightFactor": 1.0}],
        },
        tags={"team": "sim2real", "purpose": "behavioral-check"},
    )
    arn = created["arn"]
    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"

    def _cleanup():
        _error_code(lambda: batch.delete_scheduling_policy(arn=arn))

    ctx.on_cleanup(_cleanup)

    described = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]
    assert described["name"] == name, f"expected described name {name!r}, got {described['name']!r}"
    described_share_id = described["fairsharePolicy"]["shareDistribution"][0]["shareIdentifier"]
    assert described_share_id == "teamA", f"expected shareIdentifier 'teamA', got {described_share_id!r}"

    arns_before = _poll_until(
        lambda: {p["arn"] for p in _list_all_scheduling_policies(batch)},
        lambda arns: arn in arns,
        timeout_s=60,
    )
    assert arn in arns_before, f"expected {arn!r} in ListSchedulingPolicies within 60s, got {arns_before!r}"
    # ListSchedulingPolicies items only carry `arn` (no `name`); cross-check the name by
    # describing the arn that the list confirmed is present.
    listed_name = batch.describe_scheduling_policies(arns=[arn])["schedulingPolicies"][0]["name"]
    assert listed_name == name, f"expected listed policy's described name {name!r}, got {listed_name!r}"

    batch.delete_scheduling_policy(arn=arn)

    arns_after = _poll_until(
        lambda: {p["arn"] for p in _list_all_scheduling_policies(batch)},
        lambda arns: arn not in arns,
        timeout_s=90,
    )
    assert arn not in arns_after, f"expected {arn!r} absent from ListSchedulingPolicies within 90s, still present"


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as err:
        return err.response["Error"]["Code"]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _list_all_scheduling_policies(batch):
    out = []
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["nextToken"] = token
        resp = batch.list_scheduling_policies(**kwargs)
        out.extend(resp.get("schedulingPolicies", []))
        token = resp.get("nextToken")
        if not token:
            return out


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
