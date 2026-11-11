"""create-rule-retention-period-out-of-range-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-rule-retention-period-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["rbin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRule with a RetentionPeriodUnit outside the supported enum (only DAYS is
    supported) is rejected with ValidationException server-side and no rule is created;
    a request using the supported unit still succeeds."""
    rbin = ctx.client("rbin")

    marker_description = ctx.unique_name("sim2real-rbin-badunit-")
    code, message = _error(
        lambda: rbin.create_rule(
            ResourceType="EBS_SNAPSHOT",
            RetentionPeriod={"RetentionPeriodValue": 30, "RetentionPeriodUnit": "WEEKS"},
            Description=marker_description,
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value at 'retentionPeriod.retentionPeriodUnit' failed to "
        "satisfy constraint: Member must satisfy enum value set: [DAYS]"
    ), message

    matching = [r for r in _list_all(rbin, "EBS_SNAPSHOT") if r.get("Description") == marker_description]
    assert matching == [], "a rule was persisted despite the invalid-unit create failing"

    # Positive control: the only supported unit (DAYS) is accepted.
    rule_id = rbin.create_rule(
        ResourceType="EBS_SNAPSHOT",
        RetentionPeriod={"RetentionPeriodValue": 30, "RetentionPeriodUnit": "DAYS"},
        Description=ctx.unique_name("sim2real-rbin-goodunit-"),
    )["Identifier"]
    ctx.on_cleanup(lambda: rbin.delete_rule(Identifier=rule_id))
    assert rbin.get_rule(Identifier=rule_id)["RetentionPeriod"] == {
        "RetentionPeriodValue": 30,
        "RetentionPeriodUnit": "DAYS",
    }


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_all(rbin, resource_type: str) -> list[dict]:
    rules: list[dict] = []
    token = None
    while True:
        kwargs = {"ResourceType": resource_type}
        if token:
            kwargs["NextToken"] = token
        resp = rbin.list_rules(**kwargs)
        rules.extend(resp.get("Rules", []))
        token = resp.get("NextToken")
        if not token:
            break
    return rules


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
