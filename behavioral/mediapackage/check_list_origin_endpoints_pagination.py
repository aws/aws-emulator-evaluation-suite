"""list-origin-endpoints-pagination."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-origin-endpoints-pagination"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOriginEndpoints with MaxResults=1 over three endpoints returns at most one item per page, at
    least one NextToken, and exactly the three created ids with no duplicates."""
    mp = ctx.client("mediapackage")
    resource_tags = {"created-by": "sim2real"}
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id, Tags=resource_tags)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    expected_ids = set()
    for i in range(3):
        endpoint_id = ctx.unique_name(f"sim2real-mp-ep-{i}-")
        mp.create_origin_endpoint(
            Id=endpoint_id,
            ChannelId=channel_id,
            HlsPackage={"SegmentDurationSeconds": 6},
            Tags=resource_tags,
        )
        ctx.on_cleanup(lambda eid=endpoint_id: mp.delete_origin_endpoint(Id=eid))
        expected_ids.add(endpoint_id)

    seen_ids: list[str] = []
    saw_next_token = False
    next_token = None
    for _ in range(50):
        kwargs = {"ChannelId": channel_id, "MaxResults": 1}
        if next_token:
            kwargs["NextToken"] = next_token
        page = mp.list_origin_endpoints(**kwargs)
        page_ids = [ep["Id"] for ep in page["OriginEndpoints"]]
        assert len(page_ids) <= 1, f"MaxResults=1 must return at most one item per page, got {page_ids}"
        seen_ids.extend(page_ids)
        next_token = page.get("NextToken")
        if next_token:
            saw_next_token = True
        if not next_token:
            break

    assert len(seen_ids) == len(set(seen_ids)), (
        f"pagination must not return duplicate OriginEndpoints, saw {seen_ids}"
    )
    assert set(seen_ids) == expected_ids, (
        f"pagination over ChannelId={channel_id} must surface exactly the created endpoints "
        f"and nothing else: expected {expected_ids}, saw {set(seen_ids)}"
    )
    assert saw_next_token, "expected at least one NextToken while paging 3 items with MaxResults=1"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
