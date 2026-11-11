"""configuration-set-update-on-nonexistent-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "configuration-set-update-on-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateReceiptRule against a nonexistent rule set fails with RuleSetDoesNotExist and creates
    nothing, while the real rule set keeps working; after deletion it fails the same way.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference/API_CreateReceiptRule.html
    """
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-ses-rrs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: _best_effort_delete_rule_set(ses, rule_set_name))

    real_rule_name = ctx.unique_name("sim2real-ses-rule-")

    # Positive control: creating a rule against the real, existing rule set works.
    ses.create_receipt_rule(
        RuleSetName=rule_set_name,
        Rule={"Name": real_rule_name, "Enabled": True, "Actions": []},
    )
    rules = ses.describe_receipt_rule_set(RuleSetName=rule_set_name).get("Rules", [])
    assert any(r["Name"] == real_rule_name for r in rules), (
        f"expected {real_rule_name!r} in the real rule set's rules, got {rules!r}"
    )

    # Negative: the same call against a rule set that doesn't exist is rejected.
    missing_rule_set = ctx.unique_name("sim2real-ses-missing-rrs-")
    bogus_rule_name = ctx.unique_name("sim2real-ses-bogus-rule-")
    code = _error_code(
        lambda: ses.create_receipt_rule(
            RuleSetName=missing_rule_set,
            Rule={"Name": bogus_rule_name, "Enabled": True, "Actions": []},
        )
    )
    assert code == ("RuleSetDoesNotExist", f"Rule set does not exist: {missing_rule_set}"), (
        f"expected RuleSetDoesNotExist, got {code!r}"
    )

    # Effect absent: no rule set was phantom-created for the missing name...
    code2 = _error_code(
        lambda: ses.describe_receipt_rule_set(RuleSetName=missing_rule_set)
    )
    assert code2 == ("RuleSetDoesNotExist", f"Rule set does not exist: {missing_rule_set}"), (
        f"expected the never-created rule set to describe as RuleSetDoesNotExist, got {code2!r}"
    )

    # ...and the real rule set's rule list is unaffected by the rejected call.
    rules_after = ses.describe_receipt_rule_set(RuleSetName=rule_set_name).get("Rules", [])
    names_after = [r["Name"] for r in rules_after]
    assert real_rule_name in names_after, (
        f"expected {real_rule_name!r} to remain in the real rule set, got {names_after!r}"
    )
    assert bogus_rule_name not in names_after, (
        f"rejected call must not have created {bogus_rule_name!r}, got {names_after!r}"
    )
    assert len(rules_after) == len(rules), (
        f"expected rule count to stay {len(rules)}, got {len(rules_after)}"
    )

    # After delete, both a describe and a mutation fail with RuleSetDoesNotExist.
    ses.delete_receipt_rule_set(RuleSetName=rule_set_name)
    post_delete_describe_code = _error_code(
        lambda: ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
    )
    assert post_delete_describe_code == (
        "RuleSetDoesNotExist",
        f"Rule set does not exist: {rule_set_name}",
    ), (
        f"expected deleted rule set to describe as RuleSetDoesNotExist, "
        f"got {post_delete_describe_code!r}"
    )
    post_delete_mutation_code = _error_code(
        lambda: ses.create_receipt_rule(
            RuleSetName=rule_set_name,
            Rule={
                "Name": ctx.unique_name("sim2real-ses-post-delete-rule-"),
                "Enabled": True,
                "Actions": [],
            },
        )
    )
    assert post_delete_mutation_code == (
        "RuleSetDoesNotExist",
        f"Rule set does not exist: {rule_set_name}",
    ), (
        f"expected mutation against the deleted rule set to fail RuleSetDoesNotExist, "
        f"got {post_delete_mutation_code!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """The (Error.Code, Error.Message) of the ClientError fn() raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _best_effort_delete_rule_set(ses: Any, rule_set_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ses.delete_receipt_rule_set(RuleSetName=rule_set_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RuleSetDoesNotExist":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


