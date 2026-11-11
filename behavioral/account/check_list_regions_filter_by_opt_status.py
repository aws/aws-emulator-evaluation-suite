"""list-regions-filter-by-opt-status."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-regions-filter-by-opt-status"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRegions with RegionOptStatusContains=["ENABLED_BY_DEFAULT"] returns exactly the regions
    the account's own unfiltered ListRegions reports as ENABLED_BY_DEFAULT -- no more, no fewer --
    and includes us-east-1 which AWS enables by default for every commercial account."""
    account = ctx.client("account")

    def _list_regions(**extra):
        collected = []
        next_token = None
        while True:
            kwargs = {"MaxResults": 50, **extra}
            if next_token:
                kwargs["NextToken"] = next_token
            resp = account.list_regions(**kwargs)
            collected.extend(resp["Regions"])
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return collected

    # Ground truth: the account's own unfiltered listing, which also carries every
    # non-default-enabled region the filtered call must exclude.
    all_regions = _list_regions()
    expected_names = {
        r["RegionName"] for r in all_regions if r["RegionOptStatus"] == "ENABLED_BY_DEFAULT"
    }
    assert expected_names, "expected at least one ENABLED_BY_DEFAULT region in the unfiltered listing"

    filtered_regions = _list_regions(RegionOptStatusContains=["ENABLED_BY_DEFAULT"])
    for region in filtered_regions:
        assert region["RegionOptStatus"] == "ENABLED_BY_DEFAULT", region

    filtered_names = {r["RegionName"] for r in filtered_regions}
    assert filtered_names == expected_names, (filtered_names, expected_names)
    assert "us-east-1" in filtered_names, filtered_names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
