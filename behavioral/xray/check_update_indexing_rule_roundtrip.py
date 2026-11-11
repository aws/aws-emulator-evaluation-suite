"""update-indexing-rule-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-indexing-rule-roundtrip"
GROUP = 'indexing-rules'
SERVICES = ['xray']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:xray-indexing-rule")
def run(ctx) -> None:
    """UpdateIndexingRule changes a rule's sampling percentage and GetIndexingRules reflects it."""
    xr = ctx.client("xray")
    resp = xr.get_indexing_rules()
    assert "IndexingRules" in resp, f"GetIndexingRules missing IndexingRules key: {list(resp)}"
    existing = resp["IndexingRules"]
    assert isinstance(existing, list), f"IndexingRules is not a list: {existing!r}"
    assert len(existing) >= 1, "expected at least one default indexing rule"
    for rule in existing:
        assert rule.get("Name"), f"indexing rule missing Name: {rule}"
    target = existing[0]
    target_name = target["Name"]
    original_percentage = target["Rule"]["Probabilistic"]["DesiredSamplingPercentage"]

    # Pick a value guaranteed to differ from the current one.
    new_percentage = 42 if original_percentage != 42 else 43

    # Indexing rules are account-level, so the original percentage is restored in `finally`.
    try:
        resp = xr.update_indexing_rule(
            Name=target_name,
            Rule={"Probabilistic": {"DesiredSamplingPercentage": new_percentage}},
        )
        updated = resp["IndexingRule"]
        assert updated["Name"] == target_name, (
            f"expected updated rule name {target_name!r}, got {updated.get('Name')!r}"
        )
        assert (
            updated["Rule"]["Probabilistic"]["DesiredSamplingPercentage"] == new_percentage
        ), updated

        listed = xr.get_indexing_rules()["IndexingRules"]
        match = next(r for r in listed if r["Name"] == target_name)
        assert (
            match["Rule"]["Probabilistic"]["DesiredSamplingPercentage"] == new_percentage
        ), match
    finally:
        try:
            xr.update_indexing_rule(
                Name=target_name,
                Rule={"Probabilistic": {"DesiredSamplingPercentage": original_percentage}},
            )
        except Exception:
            pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
