"""get-rule-invalid-identifier-pattern-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "get-rule-invalid-identifier-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["rbin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRule with an Identifier that doesn't match the ^[0-9a-zA-Z]{11}$ pattern is
    rejected with ValidationException; GetRule on a real rule's identifier still succeeds."""
    rbin = ctx.client("rbin")

    # Positive control: a well-formed, real identifier resolves before we lean on the negative.
    rule_id = rbin.create_rule(
        ResourceType="EBS_VOLUME",
        RetentionPeriod={"RetentionPeriodValue": 2, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-validid-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))

    fetched = rbin.get_rule(Identifier=rule_id)
    assert fetched["Identifier"] == rule_id, (
        f"expected GetRule to resolve the just-created rule {rule_id!r}, got {fetched!r}"
    )

    code, message = _error(lambda: rbin.get_rule(Identifier="not-a-valid-id!"))
    assert code == "ValidationException", (
        f"expected GetRule with a malformed Identifier to be rejected with "
        f"ValidationException, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'identifier' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [0-9a-zA-Z]{11}"
    ), message


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
