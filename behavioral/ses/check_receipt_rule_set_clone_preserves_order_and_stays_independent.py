"""receipt-rule-set-clone-preserves-order-and-stays-independent."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "receipt-rule-set-clone-preserves-order-and-stays-independent"
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
        if exc.response["Error"]["Code"] != "RuleSetDoesNotExist":
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


def _rules(ses, rule_set: str) -> list[dict]:
    return ses.describe_receipt_rule_set(RuleSetName=rule_set)["Rules"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CloneReceiptRuleSet deep-copies every rule with its fields and evaluation order, edits to the
    clone leave the source untouched, and cloning onto an existing name fails with AlreadyExists.
    """
    ses = ctx.client("ses")
    source = ctx.unique_name("sim2real-behav-ses-rs-")
    clone = ctx.unique_name("sim2real-behav-ses-rs-")
    domain = ctx.unique_name("sim2real-behav-ses-") + ".example.com"

    ses.create_receipt_rule_set(RuleSetName=source)
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: ses.delete_receipt_rule_set(RuleSetName=source))
    )
    for name, recipient, tls in (
        ("alpha", f"a@{domain}", "Optional"),
        ("beta", f"b@{domain}", "Require"),
        ("gamma", f"c@{domain}", "Optional"),
    ):
        ses.create_receipt_rule(RuleSetName=source, Rule={
            "Name": name, "Enabled": True, "ScanEnabled": True, "TlsPolicy": tls,
            "Recipients": [recipient], "Actions": [],
        })
    # CreateReceiptRule prepends, so the evaluation order is the reverse of the creation order.
    source_rules = _rules(ses, source)
    assert [r["Name"] for r in source_rules] == ["gamma", "beta", "alpha"], (
        f"source order is {[r['Name'] for r in source_rules]!r}, expected "
        f"['gamma', 'beta', 'alpha']"
    )

    ses.clone_receipt_rule_set(RuleSetName=clone, OriginalRuleSetName=source)
    ctx.on_cleanup(
        lambda: _ignore_missing(lambda: ses.delete_receipt_rule_set(RuleSetName=clone))
    )
    assert {source, clone} <= _rule_set_names(ses), (
        f"after the clone, ListReceiptRuleSets is missing one of {source!r}/{clone!r}"
    )

    clone_rules = _rules(ses, clone)
    assert [r["Name"] for r in clone_rules] == ["gamma", "beta", "alpha"], (
        f"clone order is {[r['Name'] for r in clone_rules]!r}, expected the source's "
        f"['gamma', 'beta', 'alpha'] — order is evaluation order, not presentation"
    )
    assert clone_rules == source_rules, (
        f"the clone's rules differ from the source's:\n  clone  {clone_rules!r}\n  source "
        f"{source_rules!r}"
    )

    # Independence: break the clone and the source must not notice.
    ses.delete_receipt_rule(RuleSetName=clone, RuleName="beta")
    assert [r["Name"] for r in _rules(ses, clone)] == ["gamma", "alpha"], (
        f"clone order after deleting 'beta' is {[r['Name'] for r in _rules(ses, clone)]!r}, "
        f"expected ['gamma', 'alpha']"
    )
    assert _rules(ses, source) == source_rules, (
        f"deleting a rule from the clone changed the SOURCE to {_rules(ses, source)!r}; the two "
        f"rule sets must not share state"
    )

    ses.update_receipt_rule(RuleSetName=clone, Rule={
        "Name": "gamma", "Enabled": False, "ScanEnabled": False, "TlsPolicy": "Require",
        "Recipients": [f"rewritten@{domain}"], "Actions": [],
    })
    assert _rules(ses, source) == source_rules, (
        f"updating a rule in the clone changed the SOURCE to {_rules(ses, source)!r}"
    )

    # Cloning onto an occupied name is refused, and the occupant is left alone.
    code, message = _error(
        lambda: ses.clone_receipt_rule_set(RuleSetName=clone, OriginalRuleSetName=source),
        f"CloneReceiptRuleSet onto the existing rule set {clone!r}",
    )
    assert code == "AlreadyExists", f"expected AlreadyExists, got {code!r}: {message!r}"
    assert message == f"Rule set already exists: {clone}", (
        f"expected 'Rule set already exists: {clone}', got {message!r}"
    )
    assert [r["Name"] for r in _rules(ses, clone)] == ["gamma", "alpha"], (
        f"the refused clone overwrote the existing rule set: it now holds "
        f"{[r['Name'] for r in _rules(ses, clone)]!r}, expected ['gamma', 'alpha']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
