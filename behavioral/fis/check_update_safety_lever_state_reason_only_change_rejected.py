"""update-safety-lever-state-reason-only-change-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-safety-lever-state-reason-only-change-rejected"
GROUP = "safety"
SERVICES = ["fis"]

_LEVER_TERMINAL = ("engaged", "disengaged")

_REASON_ONLY_CHANGE_REJECTED = (
    "ConflictException",
    "Cannot update Safety Lever reason without a status change",
)


def _settle_safety_lever(fis, target, reason):
    """Drive the account-global safety lever to ``target`` and return the settled lever.

    AWS refuses an UpdateSafetyLeverState that repeats the current status even with a new
    reason, so a no-op leaves the prior reason in place untouched.
    """
    current = fis.get_safety_lever(id="default")["safetyLever"]
    if current["state"]["status"] == target:
        return current
    fis.update_safety_lever_state(id="default", state={"status": target, "reason": reason})
    deadline = time.monotonic() + 60
    lever = None
    while time.monotonic() < deadline:
        lever = fis.get_safety_lever(id="default")["safetyLever"]
        if lever["state"]["status"] == target:
            return lever
        time.sleep(2.0)
    raise AssertionError(f"safety lever did not settle to {target!r} (last={lever})")


def _error(fn):
    """Call fn() and return (code, message) of the ClientError it raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def expect_error(fn, code, message):
    actual_code, actual_message = _error(fn)
    assert actual_code == code, actual_code
    assert actual_message == message, (actual_message, message)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateSafetyLeverState rejects a call that repeats the lever's current status with only a
    changed reason, leaving the stored reason untouched, while a call that also changes the status
    is accepted and settles with its new reason. Cleanup always restores "disengaged"."""
    fis = ctx.client("fis")
    ctx.on_cleanup(lambda: _settle_safety_lever(fis, "disengaged", "sim2real restore to disengaged"))

    # Start from a known baseline in case a previous run left the lever engaged.
    _settle_safety_lever(fis, "disengaged", "sim2real baseline disengage")

    # Positive control: a real status change applies its reason.
    engaged_reason = "sim2real engaging to probe the reason-only rejection"
    engaged = _settle_safety_lever(fis, "engaged", engaged_reason)
    assert engaged["state"]["status"] == "engaged", engaged
    assert engaged["state"]["reason"] == engaged_reason, engaged["state"]

    # Negative: repeating the current status with only a different reason is a conflict.
    expect_error(
        lambda: fis.update_safety_lever_state(
            id="default", state={"status": "engaged", "reason": "sim2real a different reason"}
        ),
        *_REASON_ONLY_CHANGE_REJECTED,
    )

    # Effect absent: the stored reason is unchanged by the rejected call.
    unchanged = fis.get_safety_lever(id="default")["safetyLever"]
    assert unchanged["state"]["status"] == "engaged", unchanged
    assert unchanged["state"]["reason"] == engaged_reason, unchanged["state"]

    # A real status change away from "engaged" applies its own reason normally.
    disengaged_reason = "sim2real disengaging after the reason-only rejection"
    disengaged = _settle_safety_lever(fis, "disengaged", disengaged_reason)
    assert disengaged["state"]["status"] == "disengaged", disengaged
    assert disengaged["state"]["reason"] == disengaged_reason, disengaged["state"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
