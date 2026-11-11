"""lock-rule-unlock-delay-out-of-range-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lock-rule-unlock-delay-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["rbin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """LockRule with an UnlockDelayUnit outside the supported enum (only DAYS is
    supported) is rejected with ValidationException server-side and the rule stays
    unlocked; a request using the supported unit still locks it."""
    rbin = ctx.client("rbin")

    rule_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 5, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-badunitlock-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Identifier"]
    cleaned = {"done": False}
    ctx.on_cleanup(lambda: None if cleaned["done"] else rbin.delete_rule(Identifier=rule_id))

    code, message = _error(
        lambda: rbin.lock_rule(
            Identifier=rule_id, LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 10, "UnlockDelayUnit": "WEEKS"}}
        )
    )
    assert code == "ValidationException", f"expected ValidationException for UnlockDelayUnit=WEEKS, got {code!r}"
    assert message == (
        "1 validation error detected: Value at 'lockConfiguration.unlockDelay.unlockDelayUnit' "
        "failed to satisfy constraint: Member must satisfy enum value set: [DAYS]"
    ), message
    unlocked_state = rbin.get_rule(Identifier=rule_id).get("LockState")
    assert unlocked_state is None, f"rule must stay unlocked after the rejected lock_rule call, got LockState={unlocked_state!r}"

    # The rule is still unlocked, so it can still be deleted normally.
    rbin.delete_rule(Identifier=rule_id)
    cleaned["done"] = True
    gone_code, gone_message = _error(lambda: rbin.get_rule(Identifier=rule_id))
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException reading the deleted rule, got {gone_code!r}"
    assert gone_message == f"Recycle Bin Rule '{rule_id}' does not exist.", gone_message

    # Positive control: the only supported unit (DAYS) is accepted on a fresh rule.
    control_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 5, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-goodunitlock-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_unlock(ctx, control_id))
    locked = rbin.lock_rule(
        Identifier=control_id, LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 10, "UnlockDelayUnit": "DAYS"}}
    )
    assert locked["LockState"] == "locked", f"expected lock_rule response LockState='locked', got {locked.get('LockState')!r}"

    # Independent read at the destination: the mutating call's own response is not the verdict.
    fetched = rbin.get_rule(Identifier=control_id)
    assert fetched["LockState"] == "locked", f"expected get_rule LockState='locked' after locking with the supported unit, got {fetched.get('LockState')!r}"
    unlock_unit = fetched["LockConfiguration"]["UnlockDelay"]["UnlockDelayUnit"]
    assert unlock_unit == "DAYS", f"expected persisted UnlockDelayUnit='DAYS', got {unlock_unit!r}"


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
