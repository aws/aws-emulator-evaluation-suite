"""update-receipt-rule-on-nonexistent-rule-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-receipt-rule-on-nonexistent-rule-rejected"
GROUP = "overly-permissive"
SERVICES = ["ses"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateReceiptRule referencing a rule name that was never created in an existing rule
    set is rejected with RuleDoesNotExistException rather than silently creating it, the rule
    set remains empty of that rule, and updating a rule that genuinely exists still succeeds."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    never_created_rule_name = ctx.unique_name("sim2real-ses-ghost-rule-")
    phantom_rule = {
        "Name": never_created_rule_name,
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [],
        "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "ghost"}}],
        "ScanEnabled": False,
    }

    code = _error_code(
        lambda: ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=phantom_rule)
    )
    assert code == ("RuleDoesNotExist", f"Rule does not exist: {never_created_rule_name}"), (
        f"expected RuleDoesNotExist, got {code!r}"
    )

    # Effect absent: the rejected "update" must not have silently created the rule.
    describe_code = _error_code(
        lambda: ses.describe_receipt_rule(
            RuleSetName=rule_set_name, RuleName=never_created_rule_name
        )
    )
    assert describe_code == (
        "RuleDoesNotExist",
        f"Rule does not exist: {never_created_rule_name}",
    ), (
        f"phantom update against a never-created rule left it describable "
        f"(describe returned code {describe_code!r})"
    )
    rule_set = ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
    assert rule_set["Rules"] == [], "rule set unexpectedly gained a rule from the rejected update"

    # Positive control: a rule that genuinely exists can be updated.
    real_rule_name = ctx.unique_name("sim2real-ses-real-rule-")
    real_rule = {
        "Name": real_rule_name,
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [],
        "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v1"}}],
        "ScanEnabled": False,
    }
    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=real_rule)
    updated_rule = dict(real_rule)
    updated_rule["Actions"] = [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v2"}}]
    ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=updated_rule)
    described = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName=real_rule_name)["Rule"]
    assert described["Actions"][0]["AddHeaderAction"]["HeaderValue"] == "v2", (
        "positive-control update did not take effect"
    )


def _error_code(fn) -> tuple[str, str]:
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
