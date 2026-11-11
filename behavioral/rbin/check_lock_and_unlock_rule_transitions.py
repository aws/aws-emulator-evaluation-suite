"""lock-and-unlock-rule-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lock-and-unlock-rule-transitions"
GROUP = "state"
SERVICES = ["rbin"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """LockRule moves LockState null -> locked; UnlockRule then moves it locked ->
    pending_unlock and sets a future LockEndTime (= now + UnlockDelay)."""
    rbin = ctx.client("rbin")

    rule_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-locktransition-"),
        Tags=[{"Key": "sim2real-check", "Value": "lock-and-unlock-rule-transitions"}],
    )["Identifier"]
    # Once locked, min unlock delay is 7 days, so it can't be deleted within this run;
    # best-effort start the unlock countdown at teardown.
    ctx.on_cleanup(lambda: _best_effort_unlock(ctx, rule_id))

    before_lock = rbin.get_rule(Identifier=rule_id)
    assert before_lock.get("LockState") is None, f"expected no LockState before locking, got {before_lock.get('LockState')!r}"

    before_lock_time = time.time()
    locked = rbin.lock_rule(
        Identifier=rule_id, LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 7, "UnlockDelayUnit": "DAYS"}}
    )
    assert locked["LockState"] == "locked", f"expected LockState=locked from LockRule response, got {locked['LockState']!r}"

    fetched_locked = rbin.get_rule(Identifier=rule_id)
    assert fetched_locked["LockState"] == "locked", (
        f"expected LockState=locked on independent GetRule, got {fetched_locked['LockState']!r}"
    )
    assert fetched_locked["LockConfiguration"]["UnlockDelay"]["UnlockDelayValue"] == 7, (
        "expected UnlockDelayValue=7 on independent GetRule, got "
        f"{fetched_locked['LockConfiguration']['UnlockDelay']['UnlockDelayValue']!r}"
    )

    unlocked = rbin.unlock_rule(Identifier=rule_id)
    assert unlocked["LockState"] == "pending_unlock", (
        f"expected LockState=pending_unlock from UnlockRule response, got {unlocked['LockState']!r}"
    )
    lock_end = unlocked["LockEndTime"]
    # LockEndTime should be roughly now + 7 days, and strictly in the future.
    seconds_until_unlock = lock_end.timestamp() - before_lock_time
    assert 6.5 * 86400 < seconds_until_unlock < 7.5 * 86400, (
        f"expected LockEndTime ~7 days out, got {seconds_until_unlock / 86400:.2f} days"
    )

    fetched_pending = rbin.get_rule(Identifier=rule_id)
    assert fetched_pending["LockState"] == "pending_unlock", (
        f"expected LockState=pending_unlock on independent GetRule, got {fetched_pending['LockState']!r}"
    )
    assert fetched_pending["LockEndTime"] == lock_end, (
        f"expected LockEndTime to persist unchanged on independent GetRule, got "
        f"{fetched_pending['LockEndTime']!r} vs UnlockRule's {lock_end!r}"
    )
    assert fetched_pending["LockConfiguration"]["UnlockDelay"]["UnlockDelayValue"] == 7, (
        "expected UnlockDelayValue=7 to persist into pending_unlock on independent GetRule, got "
        f"{fetched_pending['LockConfiguration']['UnlockDelay']['UnlockDelayValue']!r}"
    )


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
