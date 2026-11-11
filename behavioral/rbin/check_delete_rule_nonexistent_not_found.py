"""delete-rule-nonexistent-not-found."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "delete-rule-nonexistent-not-found"
GROUP = "overly-permissive"
SERVICES = ["rbin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an Identifier that matches the rule-ID pattern but doesn't exist fails
    with ResourceNotFoundException; deleting a real, freshly created rule still succeeds."""
    rbin = ctx.client("rbin")

    fake_id = "zzzzzzzzzzz"  # matches ^[0-9a-zA-Z]{11}$ but should not exist
    code, message = _error(lambda: rbin.delete_rule(Identifier=fake_id))
    assert code == "ResourceNotFoundException", (
        f"DeleteRule on a well-formed but nonexistent Identifier: expected "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Recycle Bin Rule '{fake_id}' does not exist.", message

    # Positive control: deleting a rule that genuinely exists succeeds.
    rule_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 2, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-realdelete-"),
    )["Identifier"]
    cleaned = {"done": False}
    ctx.on_cleanup(lambda: None if cleaned["done"] else rbin.delete_rule(Identifier=rule_id))

    rbin.delete_rule(Identifier=rule_id)
    cleaned["done"] = True

    code, message = _error(lambda: rbin.get_rule(Identifier=rule_id))
    assert code == "ResourceNotFoundException", (
        f"GetRule after DeleteRule: expected ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Recycle Bin Rule '{rule_id}' does not exist.", message

    # A mutation on the now-dead id must fail the same way the delete of a
    # never-existed id did above -- a deleted rule and a nonexistent one are
    # indistinguishable to every subsequent call.
    code, message = _error(lambda: rbin.delete_rule(Identifier=rule_id))
    assert code == "ResourceNotFoundException", (
        f"DeleteRule on an already-deleted Identifier: expected "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == f"Recycle Bin Rule '{rule_id}' does not exist.", message


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
