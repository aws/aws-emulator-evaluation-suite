"""list-channels-pagination-max-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channels-pagination-max-results"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannels honors MaxResults=1 (never returns more than one page item) and
    NextToken pagination eventually surfaces every created channel."""
    mp = ctx.client("mediapackage")

    ids = [ctx.unique_name(f"sim2real-mp-pg{i}-") for i in range(3)]
    for cid in ids:
        mp.create_channel(Id=cid, Tags={"sim2real": CHECK})
        ctx.on_cleanup(lambda c=cid: mp.delete_channel(Id=c))

    seen = set()
    token = None
    for _ in range(50):
        kwargs = {"MaxResults": 1}
        if token:
            kwargs["NextToken"] = token
        resp = mp.list_channels(**kwargs)
        page = resp["Channels"]
        assert len(page) <= 1, "MaxResults=1 must never return more than one channel per page"
        seen.update(c["Id"] for c in page)
        token = resp.get("NextToken")
        if not token:
            break

    assert set(ids).issubset(seen), f"expected all created channels to be paginated through, missing {set(ids) - seen}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
