"""filter-three-way-and-across-feature-severity-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "filter-three-way-and-across-feature-severity-type"
GROUP = "filtering"
SERVICES = ["bcm-recommended-actions"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FEATURE, SEVERITY and TYPE filters in one RequestFilter return exactly the unfiltered actions
    matching all three, and every returned action carries all three values."""

    client = ctx.client("bcm-recommended-actions")
    baseline = client.list_recommended_actions()["recommendedActions"]
    if not baseline:
        raise AssertionError(
            "account has zero recommended actions; there is no write API for this "
            "service so feature/severity/type values cannot be manufactured to "
            "filter on -- needs a sandbox account with at least one action"
        )

    target = baseline[0]
    feature, severity, action_type = target["feature"], target["severity"], target["type"]
    expected_ids = {
        a["id"]
        for a in baseline
        if a["feature"] == feature and a["severity"] == severity and a["type"] == action_type
    }
    assert target["id"] in expected_ids, (
        f"target {target['id']} must match its own derived filter criteria "
        f"feature={feature!r} severity={severity!r} type={action_type!r}"
    )

    result = client.list_recommended_actions(
        filter={
            "actions": [
                {"key": "FEATURE", "matchOption": "EQUALS", "values": [feature]},
                {"key": "SEVERITY", "matchOption": "EQUALS", "values": [severity]},
                {"key": "TYPE", "matchOption": "EQUALS", "values": [action_type]},
            ]
        }
    )["recommendedActions"]
    result_ids = {a["id"] for a in result}

    assert result_ids == expected_ids, (
        f"three-way AND filter (feature={feature!r}, severity={severity!r}, "
        f"type={action_type!r}) returned ids {result_ids} but the baseline-derived "
        f"expected set is {expected_ids}"
    )
    for action in result:
        assert action["feature"] == feature, (
            f"action {action['id']} returned by FEATURE={feature!r} filter has "
            f"feature={action['feature']!r}"
        )
        assert action["severity"] == severity, (
            f"action {action['id']} returned by SEVERITY={severity!r} filter has "
            f"severity={action['severity']!r}"
        )
        assert action["type"] == action_type, (
            f"action {action['id']} returned by TYPE={action_type!r} filter has "
            f"type={action['type']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
