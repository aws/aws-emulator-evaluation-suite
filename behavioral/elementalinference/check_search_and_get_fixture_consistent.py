"""search-and-get-fixture-consistent."""
from __future__ import annotations

import datetime as dt

from behavioral_harness import tags

CHECK = "search-and-get-fixture-consistent"
GROUP = "data-plane"
SERVICES = ["elementalinference"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """SearchFixtures results are consistent with GetFixture for the same fixtureId (external sports data source)."""
    ei = ctx.client("elementalinference")
    today = dt.date.today()
    start = (today - dt.timedelta(days=6)).isoformat()
    end = today.isoformat()

    fixture = None
    for sport in ("basketball", "american-football"):
        resp = ei.search_fixtures(sport=sport, startDate=start, endDate=end, maxResults=10)
        assert isinstance(resp["fixtures"], list), f"SearchFixtures({sport}) fixtures should be a list, got {type(resp['fixtures'])!r}"
        for f in resp["fixtures"]:
            assert "fixtureId" in f and "name" in f and "status" in f, f"SearchFixtures({sport}) fixture summary missing a required field: {f!r}"
        if resp["fixtures"]:
            fixture = resp["fixtures"][0]
            break

    if fixture is None:
        raise AssertionError(
            "no fixtures were returned by the upstream sports data source for basketball/american-football "
            "in the last 7 days (data availability depends on the live season schedule); "
            "closing this gap requires a deterministic fixture fixture or a documented always-available test fixture id"
        )

    detail = ei.get_fixture(fixtureId=fixture["fixtureId"])
    assert detail["fixtureId"] == fixture["fixtureId"], (
        f"GetFixture returned fixtureId {detail['fixtureId']!r}, expected {fixture['fixtureId']!r} from SearchFixtures"
    )
    assert detail["name"] == fixture["name"], (
        f"GetFixture name {detail['name']!r} disagrees with SearchFixtures name {fixture['name']!r} for the same fixtureId"
    )
    assert detail["status"] == fixture["status"], (
        f"GetFixture status {detail['status']!r} disagrees with SearchFixtures status {fixture['status']!r} for the same fixtureId"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
