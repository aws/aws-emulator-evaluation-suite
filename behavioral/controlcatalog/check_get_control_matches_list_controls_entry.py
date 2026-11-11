"""get-control-matches-list-controls-entry."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-control-matches-list-controls-entry"
GROUP = "consistency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A control returned by ListControls resolves via GetControl to the same identity/behavior data."""
    cc = ctx.client("controlcatalog")
    page = cc.list_controls(MaxResults=5)
    controls = page.get("Controls", [])
    assert controls, "expected the Control Catalog to contain at least one control"
    summary = controls[0]

    detail = cc.get_control(ControlArn=summary["Arn"])

    assert detail["Arn"] == summary["Arn"], f"Arn mismatch: GetControl {detail['Arn']!r} != ListControls {summary['Arn']!r}"
    assert detail["Name"] == summary["Name"], f"Name mismatch for {summary['Arn']}: GetControl {detail['Name']!r} != ListControls {summary['Name']!r}"
    assert detail["Description"] == summary["Description"], (
        f"Description mismatch for {summary['Arn']}: GetControl {detail['Description']!r} != ListControls {summary['Description']!r}"
    )
    # Behavior/Severity are optional enums on the summary; compare unconditionally so an
    # absent-on-one-side divergence is caught rather than silently skipped.
    assert detail.get("Behavior") == summary.get("Behavior"), (
        f"Behavior mismatch for {summary['Arn']}: GetControl {detail.get('Behavior')!r} != ListControls {summary.get('Behavior')!r}"
    )
    assert detail.get("Severity") == summary.get("Severity"), (
        f"Severity mismatch for {summary['Arn']}: GetControl {detail.get('Severity')!r} != ListControls {summary.get('Severity')!r}"
    )
    detail_providers, summary_providers = sorted(detail.get("GovernedProviders", [])), sorted(summary.get("GovernedProviders", []))
    assert detail_providers == summary_providers, (
        f"GovernedProviders mismatch for {summary['Arn']}: GetControl {detail_providers} != ListControls {summary_providers}"
    )
    detail_aliases, summary_aliases = sorted(detail.get("Aliases", [])), sorted(summary.get("Aliases", []))
    assert detail_aliases == summary_aliases, (
        f"Aliases mismatch for {summary['Arn']}: GetControl {detail_aliases} != ListControls {summary_aliases}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
