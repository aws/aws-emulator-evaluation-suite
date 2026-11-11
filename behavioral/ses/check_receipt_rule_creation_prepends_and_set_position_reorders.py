"""receipt-rule-creation-prepends-and-set-position-reorders."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-creation-prepends-and-set-position-reorders"
GROUP = "receipt-rules"
SERVICES = ["ses"]

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


def _order(ses, rule_set: str) -> list[str]:
    return [r["Name"] for r in ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReceiptRule PREPENDS, SetReceiptRulePosition moves one rule behind another,
    ReorderReceiptRuleSet imposes an order, UpdateReceiptRule edits in place, and a delete closes
    the gap; rules are evaluated in order, so position decides which rule handles mail.
    """
    ses = ctx.client("ses")
    rule_set = ctx.unique_name("sim2real-behav-ses-rs-")
    domain = ctx.unique_name("sim2real-behav-ses-") + ".example.com"

    ses.create_receipt_rule_set(RuleSetName=rule_set)
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set))
    )
    assert rule_set in _rule_set_names(ses), (
        f"{rule_set!r} is missing from ListReceiptRuleSets after CreateReceiptRuleSet"
    )

    def _add(name: str, recipient: str) -> None:
        ses.create_receipt_rule(RuleSetName=rule_set, Rule={
            "Name": name, "Enabled": True, "ScanEnabled": True, "TlsPolicy": "Optional",
            "Recipients": [recipient], "Actions": [],
        })
        ctx.on_cleanup(lambda: _ignore_missing(
            lambda: ses.delete_receipt_rule(RuleSetName=rule_set, RuleName=name)
        ))

    first, second, third = "first", "second", "third"
    _add(first, f"a@{domain}")
    assert _order(ses, rule_set) == [first], (
        f"one rule in, order is {_order(ses, rule_set)!r}, expected {[first]!r}"
    )
    _add(second, f"b@{domain}")
    assert _order(ses, rule_set) == [second, first], (
        f"order after the second create is {_order(ses, rule_set)!r}, expected "
        f"{[second, first]!r} — CreateReceiptRule prepends"
    )
    _add(third, f"c@{domain}")
    assert _order(ses, rule_set) == [third, second, first], (
        f"order after the third create is {_order(ses, rule_set)!r}, expected "
        f"{[third, second, first]!r} — CreateReceiptRule prepends"
    )

    ses.set_receipt_rule_position(RuleSetName=rule_set, RuleName=third, After=first)
    assert _order(ses, rule_set) == [second, first, third], (
        f"after moving {third!r} behind {first!r} the order is {_order(ses, rule_set)!r}, "
        f"expected {[second, first, third]!r}"
    )

    ses.reorder_receipt_rule_set(RuleSetName=rule_set, RuleNames=[first, third, second])
    assert _order(ses, rule_set) == [first, third, second], (
        f"after ReorderReceiptRuleSet the order is {_order(ses, rule_set)!r}, expected "
        f"{[first, third, second]!r}"
    )

    ses.update_receipt_rule(RuleSetName=rule_set, Rule={
        "Name": third, "Enabled": False, "ScanEnabled": False, "TlsPolicy": "Require",
        "Recipients": [f"moved@{domain}"], "Actions": [],
    })
    assert _order(ses, rule_set) == [first, third, second], (
        f"UpdateReceiptRule moved the rule: order is now {_order(ses, rule_set)!r}, expected "
        f"{[first, third, second]!r} — an update edits in place"
    )
    updated = ses.describe_receipt_rule(RuleSetName=rule_set, RuleName=third)["Rule"]
    assert updated["Recipients"] == [f"moved@{domain}"], (
        f"updated recipients are {updated['Recipients']!r}, expected {[f'moved@{domain}']!r}"
    )
    assert updated["Enabled"] is False, f"updated rule reports Enabled={updated['Enabled']!r}"
    assert updated["TlsPolicy"] == "Require", (
        f"updated rule reports TlsPolicy={updated['TlsPolicy']!r}, expected 'Require'"
    )

    ses.delete_receipt_rule(RuleSetName=rule_set, RuleName=third)
    assert _order(ses, rule_set) == [first, second], (
        f"after deleting {third!r} the order is {_order(ses, rule_set)!r}, expected "
        f"{[first, second]!r} — the remaining rules keep their relative order"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
