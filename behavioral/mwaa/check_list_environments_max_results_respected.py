"""list-environments-max-results-respected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-environments-max-results-respected"
GROUP = "control-plane"
SERVICES = ["mwaa"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MaxResults=1 ListEnvironments page holds at most one item with a NextToken exactly when more
    exist, and paging with MaxResults=1 collects the same set as an unbounded listing, without
    duplicates.
    """
    mwaa = ctx.client("mwaa")

    before = _full_listing(mwaa)

    bounded = mwaa.list_environments(MaxResults=1)
    assert "Environments" in bounded, f"ListEnvironments response missing 'Environments': {bounded}"
    assert isinstance(bounded["Environments"], list), (
        f"Environments should be a list, got {type(bounded['Environments'])}"
    )
    assert len(bounded["Environments"]) <= 1, (
        f"MaxResults=1 returned {len(bounded['Environments'])} environments"
    )
    if bounded["Environments"]:
        assert isinstance(bounded["Environments"][0], str), (
            f"expected an environment name (str), got {type(bounded['Environments'][0])}"
        )

    collected = list(bounded["Environments"])
    first_token = bounded.get("NextToken")
    next_token = first_token
    for _ in range(50):
        if not next_token:
            break
        page = mwaa.list_environments(MaxResults=1, NextToken=next_token)
        assert len(page["Environments"]) <= 1, (
            f"MaxResults=1 page returned {len(page['Environments'])} environments"
        )
        collected.extend(page["Environments"])
        next_token = page.get("NextToken")
    assert not next_token, "paging with MaxResults=1 did not reach a page without NextToken"

    after = _full_listing(mwaa)
    # Environments other runs create or delete meanwhile may or may not be listed; an environment
    # in both unbounded listings is listed throughout the walk, and nothing outside them is.
    stable = before & after
    seen = set(collected)
    assert len(collected) == len(seen), f"paging with MaxResults=1 repeated an environment: {collected}"
    assert stable <= seen, (
        f"paging with MaxResults=1 missed {sorted(stable - seen)}, which both unbounded listings hold"
    )
    assert seen <= before | after, (
        f"paging with MaxResults=1 returned {sorted(seen - (before | after))}, which neither "
        f"unbounded listing holds"
    )
    if stable:
        assert bounded["Environments"], (
            f"MaxResults=1 returned no environment while {sorted(stable)} exist"
        )
    if len(stable) > 1:
        assert first_token, (
            f"MaxResults=1 returned no NextToken while {len(stable)} environments exist"
        )
    if len(before | after) <= 1:
        assert not first_token, (
            f"MaxResults=1 returned a NextToken while at most one environment exists: {bounded}"
        )


def _full_listing(mwaa) -> set[str]:
    full: list[str] = []
    next_token = None
    for _ in range(50):
        kwargs = {"MaxResults": 25}
        if next_token:
            kwargs["NextToken"] = next_token
        page = mwaa.list_environments(**kwargs)
        full.extend(page["Environments"])
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert not next_token, "did not reach the end of ListEnvironments within 50 pages of 25"
    return set(full)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
