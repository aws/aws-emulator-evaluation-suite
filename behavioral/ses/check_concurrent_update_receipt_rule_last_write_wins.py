"""concurrent-update-receipt-rule-last-write-wins."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-receipt-rule-last-write-wins"
GROUP = "concurrency"
SERVICES = ["ses"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateReceiptRule calls against the same rule resolve
    deterministically to exactly one final action set, never a merge/corruption
    of both writers' actions."""
    ses = ctx.client("ses")
    rule_set_name = ctx.unique_name("sim2real-ses-rs-")
    ses.create_receipt_rule_set(RuleSetName=rule_set_name)
    ctx.on_cleanup(lambda: ses.delete_receipt_rule_set(RuleSetName=rule_set_name))

    base_rule = {
        "Name": "racer-rule",
        "Enabled": True,
        "Recipients": [],
        "Actions": [{"StopAction": {"Scope": "RuleSet"}}],
    }
    ses.create_receipt_rule(RuleSetName=rule_set_name, Rule=base_rule)

    def _make_update(tag: str):
        rule = {
            "Name": "racer-rule",
            "Enabled": True,
            "Recipients": [],
            "Actions": [{"AddHeaderAction": {"HeaderName": "X-Sim2Real-Racer", "HeaderValue": tag}}],
        }

        def _call():
            ses.update_receipt_rule(RuleSetName=rule_set_name, Rule=rule)

        return _call

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_make_update("value-A")), pool.submit(_make_update("value-B"))]
        for fut in futures:
            fut.result()  # both writers must succeed cleanly, no exception

    described = ses.describe_receipt_rule(RuleSetName=rule_set_name, RuleName="racer-rule")["Rule"]
    actions = described["Actions"]
    assert len(actions) == 1, f"expected exactly one action after two racing updates, got {actions!r}"
    header_action = actions[0]["AddHeaderAction"]
    assert header_action["HeaderName"] == "X-Sim2Real-Racer", (
        f"expected the surviving action's header name to be X-Sim2Real-Racer, got {header_action!r}"
    )
    assert header_action["HeaderValue"] in ("value-A", "value-B"), (
        f"expected the surviving header value to be exactly one racer's value (value-A or "
        f"value-B), got {header_action['HeaderValue']!r} -- indicates a torn/corrupted write"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
