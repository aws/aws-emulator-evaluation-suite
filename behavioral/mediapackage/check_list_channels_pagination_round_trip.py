"""list-channels-pagination-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channels-pagination-round-trip"
GROUP = "data-plane"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannels with a small MaxResults returns at most MaxResults items plus a
    NextToken, and following that NextToken to exhaustion eventually surfaces every
    Channel created in this run exactly once (no duplicates, no omissions)."""
    mp = ctx.client("mediapackage")
    channel_ids = [ctx.unique_name(f"sim2real-mp-ch-pg{i}-") for i in range(3)]
    for cid in channel_ids:
        mp.create_channel(Id=cid, Tags={"sim2real-check": CHECK})
        ctx.on_cleanup(lambda cid=cid: mp.delete_channel(Id=cid))

    first_page = mp.list_channels(MaxResults=2)
    assert len(first_page["Channels"]) <= 2, (
        f"MaxResults=2 must return at most 2 channels, got {len(first_page['Channels'])}"
    )

    seen: list[str] = [c["Id"] for c in first_page["Channels"]]
    token = first_page.get("NextToken")
    pages_followed = 0
    while token and pages_followed < 200:
        page = mp.list_channels(MaxResults=2, NextToken=token)
        seen.extend(c["Id"] for c in page["Channels"])
        token = page.get("NextToken")
        pages_followed += 1

    assert len(seen) == len(set(seen)), "pagination must not return duplicate Channels"
    for cid in channel_ids:
        assert cid in seen, f"channel {cid} missing from paginated ListChannels traversal"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
