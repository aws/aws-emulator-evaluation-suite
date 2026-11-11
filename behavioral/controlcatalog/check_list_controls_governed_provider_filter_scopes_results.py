"""list-controls-governed-provider-filter-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-governed-provider-filter-scopes-results"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ControlFilter.GovernedProviders narrows ListControls to only controls that govern that provider."""
    cc = ctx.client("controlcatalog")

    target_provider = None
    anchor_arn = None
    token = None
    for _ in range(10):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_controls(**kwargs)
        for control in page.get("Controls", []):
            providers = control.get("GovernedProviders") or []
            if providers:
                target_provider = providers[0]
                anchor_arn = control["Arn"]
                break
        if target_provider:
            break
        token = page.get("NextToken")
        if not token:
            break

    assert target_provider, "expected at least one control with a non-empty GovernedProviders list"

    filtered = cc.list_controls(
        MaxResults=100, Filter={"GovernedProviders": [target_provider]}
    ).get("Controls", [])
    assert filtered, f"expected at least one control governed by provider {target_provider}"

    for control in filtered:
        assert target_provider in (control.get("GovernedProviders") or []), (
            f"control {control['Arn']} returned by GovernedProviders={target_provider} filter "
            "does not list that provider"
        )

    assert any(control["Arn"] == anchor_arn for control in filtered), (
        f"control {anchor_arn}, whose own GovernedProviders sourced the filter value "
        f"{target_provider}, was not present in the filtered result set"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
