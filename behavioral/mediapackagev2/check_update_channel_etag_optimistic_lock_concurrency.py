"""update-channel-etag-optimistic-lock-concurrency."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-channel-etag-optimistic-lock-concurrency"
GROUP = "concurrency"
SERVICES = ["mediapackagev2"]


def _update(mp, group_name, channel_name, etag, description):
    try:
        resp = mp.update_channel(
            ChannelGroupName=group_name, ChannelName=channel_name, ETag=etag, Description=description
        )
        return ("ok", resp)
    except ClientError as e:
        return (e.response["Error"]["Code"], None)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateChannel calls sharing one stale ETag: exactly one wins, the other gets ConflictException."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    created = mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    original_etag = created["ETag"]

    descriptions = ["racer-a", "racer-b"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda d: _update(mp, group_name, channel_name, original_etag, d), descriptions)
        )

    statuses = [r[0] for r in results]
    successes = [r for r in results if r[0] == "ok"]
    failures = [s for s in statuses if s != "ok"]

    assert len(successes) == 1, f"expected exactly one winner, got statuses={statuses}"
    assert len(failures) == 1, f"expected exactly one loser, got statuses={statuses}"
    assert failures[0] == "ConflictException", f"loser's error code was {failures[0]!r}, not ConflictException"

    winning_description = descriptions[statuses.index("ok")]
    final = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert final["Description"] == winning_description, (
        f"expected Description {winning_description!r} (the winner's), got {final['Description']!r}"
    )
    assert final["ETag"] != original_etag, "ETag did not rotate after the winning update"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
