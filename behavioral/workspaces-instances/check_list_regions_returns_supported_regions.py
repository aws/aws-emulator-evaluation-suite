"""list-regions-returns-supported-regions."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "list-regions-returns-supported-regions"
GROUP = "control-plane"
SERVICES = ["workspaces-instances"]

_REGION_NAME_PATTERN = re.compile(r"^[-0-9a-z]{1,31}$")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRegions returns a non-empty list of distinct, pattern-valid region names that includes the
    calling region, and MaxResults 1 and 5 each return the full list with no NextToken.
    """
    wsi = ctx.client("workspaces-instances")

    resp = wsi.list_regions()
    regions = resp["Regions"]
    assert len(regions) > 0

    region_names = []
    for region in regions:
        name = region["RegionName"]
        assert isinstance(name, str) and _REGION_NAME_PATTERN.match(name), (
            f"RegionName {name!r} does not match the modelled pattern "
            f"{_REGION_NAME_PATTERN.pattern!r}"
        )
        region_names.append(name)

    assert len(set(region_names)) == len(region_names), "duplicate region entries returned"
    assert ctx.region in region_names, (
        f"calling region {ctx.region!r} is absent from its own ListRegions answer: {region_names}"
    )

    for max_results in (1, 5):
        page_resp = wsi.list_regions(MaxResults=max_results)
        page_names = [r["RegionName"] for r in page_resp["Regions"]]
        assert set(page_names) == set(region_names), (
            f"MaxResults={max_results} returned {sorted(set(page_names))}, expected the "
            f"full catalog {sorted(set(region_names))}"
        )
        assert page_resp.get("NextToken") is None, (
            f"MaxResults={max_results} unexpectedly returned NextToken="
            f"{page_resp.get('NextToken')!r} -- ListRegions has apparently started "
            f"truncating and this check's no-truncation assumption needs re-verifying"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
