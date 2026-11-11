"""indexing-rule-empty-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "indexing-rule-empty-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["xray"]


def _find_rule(rules: list, name: str) -> dict:
    for rule in rules:
        if rule["Name"] == name:
            return rule
    raise AssertionError(f"indexing rule {name!r} not found in GetIndexingRules")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:xray-indexing-rule")
def run(ctx) -> None:
    """An explicit DesiredSamplingPercentage of 0.0 persists as 0.0 rather than being treated as
    unset, and a later fractional value takes effect exactly, in both the echo and GetIndexingRules.
    """
    xray = ctx.client("xray")

    initial = xray.get_indexing_rules()["IndexingRules"]
    # GetIndexingRules.IndexingRules is modeled with a minimum of 1 item -- X-Ray
    # always has at least one built-in indexing rule to update.
    assert initial, "expected GetIndexingRules to return at least one built-in rule"
    target = initial[0]
    rule_name = target["Name"]
    original_desired = target["Rule"]["Probabilistic"]["DesiredSamplingPercentage"]

    def _restore() -> None:
        xray.update_indexing_rule(
            Name=rule_name,
            Rule={"Probabilistic": {"DesiredSamplingPercentage": original_desired}},
        )

    ctx.on_cleanup(_restore)

    zero_resp = xray.update_indexing_rule(
        Name=rule_name, Rule={"Probabilistic": {"DesiredSamplingPercentage": 0.0}}
    )["IndexingRule"]
    zero_echo = zero_resp["Rule"]["Probabilistic"]["DesiredSamplingPercentage"]
    assert zero_echo == 0.0, (
        f"UpdateIndexingRule response should echo DesiredSamplingPercentage=0.0, got {zero_echo!r}"
    )

    after_zero = _find_rule(xray.get_indexing_rules()["IndexingRules"], rule_name)
    desired_after_zero = after_zero["Rule"]["Probabilistic"]["DesiredSamplingPercentage"]
    assert desired_after_zero == 0.0, (
        f"explicit DesiredSamplingPercentage=0.0 was not preserved, got {desired_after_zero!r}"
    )

    fractional = 12.375
    frac_resp = xray.update_indexing_rule(
        Name=rule_name, Rule={"Probabilistic": {"DesiredSamplingPercentage": fractional}}
    )["IndexingRule"]
    frac_echo = frac_resp["Rule"]["Probabilistic"]["DesiredSamplingPercentage"]
    assert frac_echo == fractional, (
        f"UpdateIndexingRule response should echo DesiredSamplingPercentage={fractional!r}, got {frac_echo!r}"
    )

    after_frac = _find_rule(xray.get_indexing_rules()["IndexingRules"], rule_name)
    desired_after_frac = after_frac["Rule"]["Probabilistic"]["DesiredSamplingPercentage"]
    assert desired_after_frac == fractional, (
        f"fractional DesiredSamplingPercentage was not preserved exactly, got {desired_after_frac!r}"
    )
    assert desired_after_frac != 0.0, (
        "fractional update should have moved the rule off its earlier explicit zero, "
        f"got {desired_after_frac!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
