"""get-control-matches-list-controls-summary."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-matches-list-controls-summary"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetControl on an ARN taken from ListControls returns fields consistent with the list summary."""
    cc = ctx.client("controlcatalog")
    summary_page = cc.list_controls(MaxResults=1)["Controls"]
    if not summary_page:
        raise AssertionError("ListControls returned no controls to validate against")
    entry = summary_page[0]
    detail = cc.get_control(ControlArn=entry["Arn"])

    assert detail["Arn"] == entry["Arn"], f"Arn mismatch: detail={detail['Arn']!r} list={entry['Arn']!r}"
    assert detail["Name"] == entry["Name"], f"Name mismatch: detail={detail['Name']!r} list={entry['Name']!r}"
    assert detail["Description"] == entry["Description"], (
        f"Description mismatch: detail={detail['Description']!r} list={entry['Description']!r}"
    )
    assert detail.get("Behavior") == entry.get("Behavior"), (
        f"Behavior mismatch: detail={detail.get('Behavior')!r} list={entry.get('Behavior')!r}"
    )
    assert detail.get("Severity") == entry.get("Severity"), (
        f"Severity mismatch: detail={detail.get('Severity')!r} list={entry.get('Severity')!r}"
    )
    assert detail.get("ParameterRequirementSummary") == entry.get("ParameterRequirementSummary"), (
        f"ParameterRequirementSummary mismatch: detail={detail.get('ParameterRequirementSummary')!r} "
        f"list={entry.get('ParameterRequirementSummary')!r}"
    )
    assert sorted(detail.get("GovernedProviders", [])) == sorted(entry.get("GovernedProviders", [])), (
        f"GovernedProviders mismatch: detail={sorted(detail.get('GovernedProviders', []))} "
        f"list={sorted(entry.get('GovernedProviders', []))}"
    )
    assert sorted(detail.get("GovernedResources", [])) == sorted(entry.get("GovernedResources", [])), (
        f"GovernedResources mismatch: detail={sorted(detail.get('GovernedResources', []))} "
        f"list={sorted(entry.get('GovernedResources', []))}"
    )

    detail_impl = detail.get("Implementation") or {}
    entry_impl = entry.get("Implementation") or {}
    assert detail_impl.get("Type") == entry_impl.get("Type"), (
        f"Implementation.Type mismatch: detail={detail_impl.get('Type')!r} list={entry_impl.get('Type')!r}"
    )
    assert detail_impl.get("Identifier") == entry_impl.get("Identifier"), (
        f"Implementation.Identifier mismatch: detail={detail_impl.get('Identifier')!r} "
        f"list={entry_impl.get('Identifier')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
