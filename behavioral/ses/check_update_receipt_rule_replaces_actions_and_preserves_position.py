"""update-receipt-rule-replaces-actions-and-preserves-position."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-receipt-rule-replaces-actions-and-preserves-position"
GROUP = "state-machine"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateReceiptRule replaces a rule's actions/settings in place while its
    position within the rule set (relative order vs sibling rules) stays fixed."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    rule_a = {"Name": "rule-a", "Enabled": True, "Recipients": [], "Actions": [{"StopAction": {"Scope": "RuleSet"}}]}
    rule_b_v1 = {
        "Name": "rule-b",
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [],
        "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v1"}}],
        "ScanEnabled": False,
    }
    rule_c = {"Name": "rule-c", "Enabled": True, "Recipients": [], "Actions": [{"StopAction": {"Scope": "RuleSet"}}]}

    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=rule_a)
    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=rule_b_v1, After="rule-a")
    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=rule_c, After="rule-b")

    before = ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
    order_before = [r["Name"] for r in before["Rules"]]
    assert order_before == ["rule-a", "rule-b", "rule-c"], order_before

    rule_b_v2 = {
        "Name": "rule-b",
        "Enabled": True,
        "TlsPolicy": "Optional",
        "Recipients": [],
        "Actions": [
            {"AddHeaderAction": {"HeaderName": "X-Sim2Real", "HeaderValue": "v2"}},
            {"StopAction": {"Scope": "RuleSet"}},
        ],
        "ScanEnabled": False,
    }
    ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=rule_b_v2)

    after = ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
    order_after = [r["Name"] for r in after["Rules"]]
    assert order_after == ["rule-a", "rule-b", "rule-c"], order_after

    described = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName="rule-b")["Rule"]
    actions = described["Actions"]
    assert len(actions) == 2, actions
    assert actions[0]["AddHeaderAction"]["HeaderValue"] == "v2", actions[0]
    assert "StopAction" in actions[1], actions[1]
    # the v1-only header value must be fully gone, not merged alongside v2
    header_values = [a["AddHeaderAction"]["HeaderValue"] for a in actions if "AddHeaderAction" in a]
    assert header_values == ["v2"], header_values


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
