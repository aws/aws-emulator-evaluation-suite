"""create-rule-with-lock-configuration-locks-immediately."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-rule-with-lock-configuration-locks-immediately"
GROUP = "lifecycle"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Supplying LockConfiguration at CreateRule time locks the rule immediately, whereas
    a rule created without one has no lock state at all."""
    rbin = ctx.client("rbin")

    locked_created = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 7, "UnlockDelayUnit": "DAYS"}},
        Description=ctx.unique_name("sim2real-rbin-lockedcreate-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    locked_id = locked_created["Identifier"]
    # A locked rule can't be deleted; best-effort start the unlock countdown so it
    # eventually becomes deletable rather than staying locked forever.
    ctx.on_cleanup(lambda: _best_effort_unlock(ctx, locked_id))
    # The claim under test is "immediately" — assert LockState off the CreateRule
    # response itself, not only off a later GetRule once Status settles.
    assert locked_created["LockState"] == "locked", (
        f"expected CreateRule to report LockState=locked immediately, got {locked_created.get('LockState')!r}"
    )

    unlocked_created = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-unlockedcreate-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    unlocked_id = unlocked_created["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=unlocked_id))
    assert unlocked_created.get("LockState") is None, (
        f"expected CreateRule with no LockConfiguration to report no lock state, got {unlocked_created.get('LockState')!r}"
    )

    locked_rule = _poll_until(
        lambda: rbin.get_rule(Identifier=locked_id),
        lambda r: r["Status"] == "available",
        timeout_s=60,
    )
    assert locked_rule["LockState"] == "locked", (
        f"expected GetRule to still report LockState=locked once available, got {locked_rule.get('LockState')!r}"
    )
    assert locked_rule["LockConfiguration"]["UnlockDelay"]["UnlockDelayValue"] == 7, (
        "expected GetRule to echo the UnlockDelayValue of 7 supplied at creation, got "
        f"{locked_rule.get('LockConfiguration')!r}"
    )

    unlocked_rule = rbin.get_rule(Identifier=unlocked_id)
    assert unlocked_rule.get("LockState") is None, (
        f"expected GetRule for a never-locked rule to report no lock state, got {unlocked_rule.get('LockState')!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _best_effort_unlock(ctx, rule_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ctx.client("rbin").unlock_rule(Identifier=rule_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
