"""receipt-rule-set-duplicate-create-delete-recreate."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-set-duplicate-create-delete-recreate"
GROUP = "receipt-rule-set"
SERVICES = ["ses"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A second CreateReceiptRuleSet for a name already in use is refused AlreadyExists, and the
    rule set keeps its original CreatedTimestamp and empty Rules; after DeleteReceiptRuleSet and
    a repeat of it the name is undescribable, and a fresh create for it then succeeds anew.
    """
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-rrs-cycle-")

    _already_exists = ("AlreadyExists", f"Rule set already exists: {name}")
    _does_not_exist = ("RuleSetDoesNotExist", f"Rule set does not exist: {name}")

    ses.create_receipt_rule_set(RuleSetName=name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=name))

    first = ses.describe_receipt_rule_set(RuleSetName=name)
    first_created = first["Metadata"]["CreatedTimestamp"]
    assert first["Rules"] == [], f"a fresh rule set had rules {first['Rules']!r}, expected none"

    expect_error(lambda: ses.create_receipt_rule_set(RuleSetName=name), *_already_exists)

    survived = ses.describe_receipt_rule_set(RuleSetName=name)
    assert survived["Metadata"]["CreatedTimestamp"] == first_created, (
        f"CreatedTimestamp changed from {first_created!r} to "
        f"{survived['Metadata']['CreatedTimestamp']!r} after a refused duplicate create"
    )
    assert survived["Rules"] == [], (
        f"a refused duplicate create left rules {survived['Rules']!r}, expected none"
    )

    ses.delete_receipt_rule_set(RuleSetName=name)
    expect_error(lambda: ses.describe_receipt_rule_set(RuleSetName=name), *_does_not_exist)

    ses.delete_receipt_rule_set(RuleSetName=name)
    expect_error(lambda: ses.describe_receipt_rule_set(RuleSetName=name), *_does_not_exist)

    ses.create_receipt_rule_set(RuleSetName=name)
    recreated = ses.describe_receipt_rule_set(RuleSetName=name)
    assert recreated["Rules"] == [], (
        f"the recreated rule set had rules {recreated['Rules']!r}, expected none"
    )
    assert recreated["Metadata"]["CreatedTimestamp"] != first_created, (
        "the recreated rule set kept the original CreatedTimestamp "
        f"{first_created!r} instead of getting a new one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
