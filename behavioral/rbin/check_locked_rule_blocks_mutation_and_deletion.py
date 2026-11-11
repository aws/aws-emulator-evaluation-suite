"""locked-rule-blocks-mutation-and-deletion."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "locked-rule-blocks-mutation-and-deletion"
GROUP = "overly-permissive"
SERVICES = ["rbin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A locked (or pending_unlock) rule rejects both UpdateRule and DeleteRule with
    ConflictException and its state doesn't change; an unlocked sibling rule accepts
    both operations normally."""
    rbin = ctx.client("rbin")

    guarded_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description="original description",
    )["Identifier"]
    ctx.on_cleanup(lambda: _best_effort_unlock(ctx, guarded_id))

    control_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 7, "RetentionPeriodUnit": "DAYS"},
        Description="control description",
    )["Identifier"]
    cleaned = {"done": False}
    ctx.on_cleanup(lambda: None if cleaned["done"] else rbin.delete_rule(Identifier=control_id))

    rbin.lock_rule(
        Identifier=guarded_id, LockConfiguration={"UnlockDelay": {"UnlockDelayValue": 7, "UnlockDelayUnit": "DAYS"}}
    )

    # Locked: UpdateRule rejected, description unchanged.
    code, message = _error(lambda: rbin.update_rule(Identifier=guarded_id, Description="attempted while locked"))
    assert code == "ConflictException", f"expected ConflictException from UpdateRule on a locked rule, got {code!r}"
    assert message == f"Cannot modify Recycle Bin rule {guarded_id} because it is locked.", message
    desc = rbin.get_rule(Identifier=guarded_id)["Description"]
    assert desc == "original description", f"expected description unchanged after rejected update, got {desc!r}"

    # Locked: DeleteRule rejected, rule still exists.
    code, message = _error(lambda: rbin.delete_rule(Identifier=guarded_id))
    assert code == "ConflictException", f"expected ConflictException from DeleteRule on a locked rule, got {code!r}"
    assert message == f"Cannot delete Recycle Bin rule {guarded_id} because it is locked.", message
    ident = rbin.get_rule(Identifier=guarded_id)["Identifier"]
    assert ident == guarded_id, f"expected guarded rule to still exist after rejected delete, got {ident!r}"

    # pending_unlock: DeleteRule still rejected (unlock delay hasn't elapsed).
    rbin.unlock_rule(Identifier=guarded_id)
    state = rbin.get_rule(Identifier=guarded_id)["LockState"]
    assert state == "pending_unlock", f"expected pending_unlock after UnlockRule, got {state!r}"
    code, message = _error(lambda: rbin.delete_rule(Identifier=guarded_id))
    assert code == "ConflictException", f"expected ConflictException from DeleteRule while pending_unlock, got {code!r}"
    assert message == f"Cannot delete Recycle Bin rule {guarded_id} because it is locked.", message
    ident = rbin.get_rule(Identifier=guarded_id)["Identifier"]
    assert ident == guarded_id, f"expected guarded rule to still exist while pending_unlock, got {ident!r}"

    # Positive control: the never-locked sibling accepts both operations normally.
    updated = rbin.update_rule(Identifier=control_id, Description="control description updated")
    got = updated["Description"]
    assert got == "control description updated", f"expected control update to take effect, got {got!r}"
    rbin.delete_rule(Identifier=control_id)
    cleaned["done"] = True


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
