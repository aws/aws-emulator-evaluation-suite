"""lock-state-transition-guards-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lock-state-transition-guards-rejected"
GROUP = "overly-permissive"
SERVICES = ["rbin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LockRule on an already-locked rule, and UnlockRule on a rule that isn't locked,
    both fail with ConflictException and leave lock state unchanged; on a sibling rule,
    the matching valid transition for each of LockRule and UnlockRule still succeeds."""
    rbin = ctx.client("rbin")

    already_locked_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-alreadylocked-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_unlock(ctx, already_locked_id))
    rbin.lock_rule(
        Identifier=already_locked_id,
        LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 7, "UnlockDelayUnit": "DAYS"}},
    )

    never_locked_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-neverlocked-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=never_locked_id))

    control_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-controllock-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_unlock(ctx, control_id))

    # Boundary 1: locking an already-locked rule is rejected.
    code, message = _error(
        lambda: rbin.lock_rule(
            Identifier=already_locked_id,
            LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 10, "UnlockDelayUnit": "DAYS"}},
        )
    )
    assert code == "ConflictException", code
    assert message == (
        f"Cannot lock Recycle Bin rule {already_locked_id} because it has a different unlock "
        "delay already set."
    ), message
    still_locked = rbin.get_rule(Identifier=already_locked_id)
    assert still_locked["LockState"] == "locked"
    assert still_locked["LockConfiguration"]["UnlockDelay"]["UnlockDelayValue"] == 7  # unchanged

    # Boundary 2: unlocking a never-locked rule is rejected.
    code, message = _error(lambda: rbin.unlock_rule(Identifier=never_locked_id))
    assert code == "ConflictException", code
    assert message == f"Cannot unlock Recycle Bin rule {never_locked_id} because it is not locked.", message
    still_never_locked = rbin.get_rule(Identifier=never_locked_id)
    assert still_never_locked.get("LockState") is None

    # Positive control: a valid lock transition on a fresh, unlocked rule still succeeds.
    locked_control = rbin.lock_rule(
        Identifier=control_id, LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 7, "UnlockDelayUnit": "DAYS"}}
    )
    assert locked_control["LockState"] == "locked"

    # Positive control: unlocking that same, validly-locked rule also succeeds. Without
    # this, boundary 2's rejection is indistinguishable from an UnlockRule that always
    # rejects regardless of state.
    unlocked_control = rbin.unlock_rule(Identifier=control_id)
    assert unlocked_control["LockState"] == "pending_unlock"
    fetched_control = rbin.get_rule(Identifier=control_id)
    assert fetched_control["LockState"] == "pending_unlock"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
