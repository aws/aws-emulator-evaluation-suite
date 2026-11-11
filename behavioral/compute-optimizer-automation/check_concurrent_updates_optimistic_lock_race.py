"""concurrent-updates-optimistic-lock-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-updates-optimistic-lock-race"
GROUP = "concurrency"
SERVICES = ["compute-optimizer-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:compute-optimizer-enrollment")
def run(ctx: Any) -> None:
    """Two concurrent UpdateAutomationRule calls racing on the same stale ruleRevision: exactly one wins,
    the other is rejected with InvalidParameterValueException (optimistic-lock conflict)."""
    client = ctx.client("compute-optimizer-automation")
    _ensure_enrolled(ctx)

    name = ctx.unique_name("sim2real-rule-")
    created = client.create_automation_rule(**_rule_kwargs(name, status="Inactive"))
    rule_arn = created["ruleArn"]
    ctx.on_cleanup(lambda: _cleanup_rule(client, rule_arn))
    base_revision = created["ruleRevision"]

    def racer(label: str):
        from botocore.exceptions import ClientError

        try:
            resp = client.update_automation_rule(
                ruleArn=rule_arn,
                ruleRevision=base_revision,
                description=f"racer-{label}",
            )
            return ("ok", label, resp)
        except ClientError as exc:
            return ("error", label, exc.response["Error"]["Code"], exc.response["Error"]["Message"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(racer, ["A", "B"]))

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]

    assert len(winners) == 1, f"expected exactly one racer to win the optimistic lock, got {results}"
    assert len(losers) == 1, f"expected exactly one racer to lose the optimistic lock, got {results}"
    assert losers[0][2] == "InvalidParameterValueException", f"unexpected loser code: {losers[0][2]!r}"

    winning_label = winners[0][1]
    winning_resp = winners[0][2]
    expected_message = (
        f"Rule revision does not match the current revision number {winning_resp['ruleRevision']}"
    )
    assert losers[0][3] == expected_message, f"unexpected loser message: {losers[0][3]!r}"

    final = client.get_automation_rule(ruleArn=rule_arn)
    assert final["description"] == f"racer-{winning_label}", (
        f"expected the winning racer's description 'racer-{winning_label}', got {final['description']!r}"
    )
    assert final["ruleRevision"] == winning_resp["ruleRevision"], (
        f"expected persisted ruleRevision {winning_resp['ruleRevision']}, got {final['ruleRevision']}"
    )


def _ensure_enrolled(ctx) -> None:
    

    co = ctx.client("compute-optimizer")
    base_status = co.get_enrollment_status().get("status")
    if base_status != "Active":
        co.update_enrollment_status(status="Active", includeMemberAccounts=False)
        # Not restored: an opt-out blocks opting back in for 24 hours.
        deadline0 = time.monotonic() + 120
        while time.monotonic() < deadline0:
            base_status = co.get_enrollment_status().get("status")
            if base_status == "Active":
                break
            if base_status == "Failed":
                raise AssertionError("compute-optimizer base enrollment failed")
            time.sleep(3)
        else:
            raise AssertionError(
                "compute-optimizer base enrollment did not reach Active within 120s",
            )

    client = ctx.client("compute-optimizer-automation")
    cfg = client.get_enrollment_configuration()
    if cfg["status"] == "Active":
        return
    if cfg["status"] in ("Inactive", "Pending", "Failed"):
        client.update_enrollment_configuration(status="Active")
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        cfg = client.get_enrollment_configuration()
        if cfg["status"] == "Active":
            return
        if cfg["status"] == "Failed":
            raise AssertionError(f"account enrollment failed: {cfg.get('statusReason')}")
        time.sleep(2)
    raise AssertionError(
        "account did not reach Active Compute Optimizer Automation enrollment status "
        "within 60s of requesting UpdateEnrollmentConfiguration(status=Active)",
    )


def _rule_kwargs(name: str, status: str = "Inactive") -> dict:
    return {
        "name": name,
        "ruleType": "AccountRule",
        "recommendedActionTypes": ["SnapshotAndDeleteUnattachedEbsVolume"],
        "schedule": {
            "scheduleExpression": "cron(30 12 * * ? *)",
            "scheduleExpressionTimezone": "UTC",
            "executionWindowInMinutes": 60,
        },
        "status": status,
        "criteria": {
            "resourceArn": [
                {
                    "comparison": "StringEquals",
                    "values": ["arn:aws:ec2:us-east-1:111122223333:volume/vol-0000000000000dead"],
                }
            ]
        },
        "tags": [{"key": "sim2real-env", "value": "behavioral"}],
    }


def _cleanup_rule(client, rule_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        current = client.get_automation_rule(ruleArn=rule_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    try:
        client.delete_automation_rule(ruleArn=rule_arn, ruleRevision=current["ruleRevision"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
