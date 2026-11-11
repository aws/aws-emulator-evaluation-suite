"""list-controls-filter-by-governed-provider-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-controls-filter-by-governed-provider-scopes-results"
GROUP = "data-integrity"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControls with Filter.GovernedProviders=[X] returns only controls that govern
    resources of provider X, and still includes the control the filter value was sourced from."""

    cc = ctx.client("controlcatalog")

    provider = None
    anchor_arn = None
    next_token = None
    for _ in range(10):
        kwargs = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = cc.list_controls(**kwargs)
        for c in page["Controls"]:
            providers = c.get("GovernedProviders") or []
            if providers:
                provider = providers[0]
                anchor_arn = c["Arn"]
                break
        if provider is not None or not page.get("NextToken"):
            break
        next_token = page["NextToken"]

    if provider is None:
        raise AssertionError(
            "no control in the first ~1000 scanned reports a non-empty GovernedProviders; "
            "closeable by scanning the full catalog instead of the first 10 pages"
        )

    filtered = cc.list_controls(Filter={"GovernedProviders": [provider]}, MaxResults=100)
    items = filtered["Controls"]

    assert len(items) >= 1, "filtering by a provider sourced from a real control returned nothing"
    assert all(provider in (c.get("GovernedProviders") or []) for c in items), (
        "filter did not scope all results to the governed provider"
    )
    assert any(c["Arn"] == anchor_arn for c in items), "the sourcing control itself was not in the filtered set"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
