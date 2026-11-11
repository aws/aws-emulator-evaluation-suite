"""channel-creation-populates-ingest-endpoints."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "channel-creation-populates-ingest-endpoints"
GROUP = "state"
SERVICES = ["mediapackagev2"]


_CHANNEL_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel. "
    "Verify your channel name or add a channel and then try again"
)
_CHANNEL_GROUP_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel group. "
    "Verify your channel group name or add a channel group and then try again"
)


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel synchronously provisions real ingest endpoints (Id + Url), and
    GetChannel reflects the exact same set immediately afterward. After DeleteChannel and
    DeleteChannelGroup, both are gone under an independent read."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    resp = mp.create_channel(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    endpoints = resp.get("IngestEndpoints") or []
    assert len(endpoints) >= 1, f"expected at least one ingest endpoint, got {endpoints}"
    for ep in endpoints:
        assert ep.get("Url"), f"ingest endpoint missing Url: {ep}"
        assert ep.get("Id"), f"ingest endpoint missing Id: {ep}"

    got = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    got_ids = sorted(e["Id"] for e in got.get("IngestEndpoints", []))
    resp_ids = sorted(e["Id"] for e in endpoints)
    assert got_ids == resp_ids, f"GetChannel ingest endpoint ids diverged: {got_ids} != {resp_ids}"
    got_urls = sorted(e["Url"] for e in got.get("IngestEndpoints", []))
    resp_urls = sorted(e["Url"] for e in endpoints)
    assert got_urls == resp_urls, f"GetChannel ingest endpoints diverged: {got_urls} != {resp_urls}"

    mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    err = _error(
        lambda: mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err!r}"
    assert err["Message"] == _CHANNEL_NOT_FOUND, f"got {err!r}"

    mp.delete_channel_group(ChannelGroupName=group_name)
    err2 = _error(
        lambda: mp.get_channel_group(ChannelGroupName=group_name)
    )
    assert err2["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err2!r}"
    assert err2["Message"] == _CHANNEL_GROUP_NOT_FOUND, f"got {err2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
