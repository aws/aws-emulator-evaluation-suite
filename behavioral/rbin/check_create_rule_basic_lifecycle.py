"""create-rule-basic-lifecycle."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-rule-basic-lifecycle"
GROUP = "lifecycle"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created region-level rule transitions pending -> available, exposes the
    fields it was created with, has no lock state, and disappears after deletion."""
    rbin = ctx.client("rbin")

    created = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 5, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-desc-"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    rule_id = created["Identifier"]
    cleaned = {"done": False}

    def _cleanup() -> None:
        if not cleaned["done"]:
            rbin.delete_rule(Identifier=rule_id)

    ctx.on_cleanup(_cleanup)

    assert created["Status"] == "pending", f"expected a freshly created rule to be pending, got {created['Status']!r}"
    assert created["ResourceType"] == "EBS_SNAPSHOT"
    assert created["RetentionPeriod"] == {"RetentionPeriodValue": 5, "RetentionPeriodUnit": "DAYS"}
    assert created.get("LockState") is None

    rule = _poll_until(
        lambda: rbin.get_rule(Identifier=rule_id),
        lambda r: r["Status"] == "available",
        timeout_s=60,
    )
    assert rule["Identifier"] == rule_id
    assert rule["ResourceType"] == "EBS_SNAPSHOT"
    assert rule["RetentionPeriod"]["RetentionPeriodValue"] == 5
    assert rule.get("LockState") is None
    assert rule["RuleArn"].endswith(rule_id)

    rbin.delete_rule(Identifier=rule_id)
    cleaned["done"] = True

    code, message = _error(lambda: rbin.get_rule(Identifier=rule_id))
    assert code == "ResourceNotFoundException", code
    assert message == f"Recycle Bin Rule '{rule_id}' does not exist.", message


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
