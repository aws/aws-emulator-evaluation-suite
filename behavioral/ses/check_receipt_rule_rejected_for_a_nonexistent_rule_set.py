"""receipt-rule-rejected-for-a-nonexistent-rule-set."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-rejected-for-a-nonexistent-rule-set"
GROUP = "receipt-rules"
SERVICES = ["ses"]

def _error(fn, what: str) -> tuple[str, str]:
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"{what} SUCCEEDED; real AWS rejects it")


def _ignore_missing(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("RuleDoesNotExist", "RuleSetDoesNotExist"):
            raise


def _rule_set_names(ses) -> set[str]:
    """Every receipt rule set in the account, following NextToken.

    ListReceiptRuleSets has no botocore paginator, and other rule sets can push ours off page one.
    """
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        page = ses.list_receipt_rule_sets(**kwargs)
        names.update(rs["Name"] for rs in page.get("RuleSets", []))
        token = page.get("NextToken")
        if not token:
            return names


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """CreateReceiptRule against a nonexistent rule set fails with RuleSetDoesNotExist naming it,
    the rule set is NOT auto-created, and once it exists the identical call succeeds.
    """
    ses = ctx.client("ses")
    rule_set = ctx.unique_name("sim2real-behav-ses-rs-")
    domain = ctx.unique_name("sim2real-behav-ses-") + ".example.com"
    rule = {
        "Name": "inbound", "Enabled": True, "ScanEnabled": True, "TlsPolicy": "Optional",
        "Recipients": [f"a@{domain}"], "Actions": [],
    }

    # The name is one only this check occupies, so "does not exist" is a property of our query
    # rather than a snapshot of the account.
    assert rule_set not in _rule_set_names(ses), (
        f"{rule_set!r} already exists in this account; the premise of this check is broken"
    )

    code, message = _error(
        lambda: ses.create_receipt_rule(RuleSetName=rule_set, Rule=dict(rule)),
        f"CreateReceiptRule into the absent rule set {rule_set!r}",
    )
    assert code == "RuleSetDoesNotExist", (
        f"expected RuleSetDoesNotExist, got {code!r}: {message!r}"
    )
    assert message == f"Rule set does not exist: {rule_set}", (
        f"expected 'Rule set does not exist: {rule_set}', got {message!r}"
    )

    # Effect absent: the refused call did not bring the parent into existence.
    assert rule_set not in _rule_set_names(ses), (
        f"{rule_set!r} appeared in ListReceiptRuleSets after the refused CreateReceiptRule — the "
        f"rejection must not create the rule set it rejected"
    )
    code, message = _error(
        lambda: ses.describe_receipt_rule_set(RuleSetName=rule_set),
        f"DescribeReceiptRuleSet on the absent rule set {rule_set!r}",
    )
    assert code == "RuleSetDoesNotExist", (
        f"DescribeReceiptRuleSet on the absent rule set returned {code!r}: {message!r}, expected "
        f"RuleSetDoesNotExist"
    )

    # Nothing was wrong with the rule, only with the parent.
    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))
    )
    ses.create_receipt_rule(RuleSetName=rule_set, Rule=dict(rule))
    ctx.on_cleanup(lambda: _ignore_missing(
        lambda: ses.delete_receipt_rule(RuleSetName=rule_set, RuleName=rule["Name"])
    ))
    landed = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=rule["Name"])["Rule"]
    assert landed["Recipients"] == rule["Recipients"], (
        f"the identical rule, once the rule set existed, came back with recipients "
        f"{landed['Recipients']!r}, expected {rule['Recipients']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
