"""get-region-opt-status-matches-list-regions-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-region-opt-status-matches-list-regions-consistency"
GROUP = "state"
SERVICES = ["account"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRegionOptStatus agrees with the status ListRegions reports, for every Region in the
    account's catalog -- the two read paths must not disagree about account state, whatever mix
    of ENABLED_BY_DEFAULT, ENABLED and DISABLED Regions this account currently has."""
    account = ctx.client("account")

    all_regions = []
    next_token = None
    while True:
        kwargs = {"MaxResults": 50}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = account.list_regions(**kwargs)
        all_regions.extend(resp["Regions"])
        next_token = resp.get("NextToken")
        if not next_token:
            break

    assert len(all_regions) >= 10, f"expected the real multi-region catalog, got {all_regions}"

    seen_names = set()
    statuses_seen = set()
    for region in all_regions:
        name = region["RegionName"]
        assert name not in seen_names, f"{name} listed twice by ListRegions: {all_regions}"
        seen_names.add(name)

        direct_status = account.get_region_opt_status(RegionName=name)["RegionOptStatus"]
        assert direct_status == region["RegionOptStatus"], (
            f"{name}: ListRegions reports RegionOptStatus={region['RegionOptStatus']!r} but "
            f"GetRegionOptStatus reports {direct_status!r} for the same Region"
        )
        statuses_seen.add(direct_status)

    assert "ENABLED_BY_DEFAULT" in statuses_seen, (
        f"expected at least one ENABLED_BY_DEFAULT region (e.g. us-east-1), saw {statuses_seen}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
