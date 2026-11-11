"""list-scheduling-policies-reflects-created."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "list-scheduling-policies-reflects-created"
GROUP = "scheduling-policy"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSchedulingPolicies enumerates all scheduling policies created in the account,
    independent of the per-ARN detail returned only by DescribeSchedulingPolicies, and omits
    a policy again once it is deleted."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")

    created = batch.create_scheduling_policy(
        name=name,
        fairsharePolicy={
            "shareDecaySeconds": 300,
            "computeReservation": 25,
            # Real AWS Batch validates shareIdentifier against a strict pattern that rejects
            # underscores (ClientException: "ShareIdentifier name should match a valid pattern.");
            # stick to plain alphanumerics, which are always accepted.
            "shareDistribution": [{"shareIdentifier": "teama", "weightFactor": 1.0}],
        },
        tags={"sim2real": "true"},
    )
    policy_arn = created["arn"]
    ctx.on_cleanup(lambda: _best_effort_delete(batch, policy_arn))

    def _list_all() -> list[dict]:
        out = []
        next_token = None
        while True:
            kwargs = {"maxResults": 100}
            if next_token:
                kwargs["nextToken"] = next_token
            page = batch.list_scheduling_policies(**kwargs)
            entries = page.get("schedulingPolicies", [])
            assert all(set(e.keys()) == {"arn"} for e in entries), "list entries carry only 'arn'"
            out.extend(entries)
            next_token = page.get("nextToken")
            if not next_token:
                return out

    # ListSchedulingPolicies only ever returns bare ARNs (no name/policy body) - paginate the full
    # account listing and confirm our ARN is present exactly once.
    matches = [e for e in _list_all() if e["arn"] == policy_arn]
    assert len(matches) == 1, f"expected exactly one listing entry for {policy_arn}, found {len(matches)}"

    # The name/detail is only obtainable via DescribeSchedulingPolicies, and must match creation.
    detail = batch.describe_scheduling_policies(arns=[policy_arn])["schedulingPolicies"][0]
    assert detail["name"] == name
    assert detail["fairsharePolicy"]["computeReservation"] == 25

    # The cleanup delete is otherwise a free negative left unasserted: prove the policy is
    # actually gone at both independent readers, not merely that DeleteSchedulingPolicy returned 200.
    batch.delete_scheduling_policy(arn=policy_arn)

    def _still_listed() -> bool:
        return any(e["arn"] == policy_arn for e in _list_all())

    _poll_until(_still_listed, lambda listed: not listed, timeout_s=90)
    remaining = batch.describe_scheduling_policies(arns=[policy_arn])["schedulingPolicies"]
    assert remaining == [], f"deleted policy {policy_arn} still describable: {remaining}"


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _best_effort_delete(batch: Any, arn: str) -> None:
    batch.delete_scheduling_policy(arn=arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
