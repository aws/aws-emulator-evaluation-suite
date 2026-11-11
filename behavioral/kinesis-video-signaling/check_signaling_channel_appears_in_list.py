"""signaling-channel-appears-in-list."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "signaling-channel-appears-in-list"
GROUP = "control-plane"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created signaling channel shows up in ListSignalingChannels when filtered
    by a name-prefix condition, with the correct type and ARN."""
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-list-")
    arn = kv.create_signaling_channel(
        ChannelName=name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ChannelARN"]
    ctx.on_cleanup(lambda: kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")

    listing = kv.list_signaling_channels(
        ChannelNameCondition={"ComparisonOperator": "BEGINS_WITH", "ComparisonValue": name}
    )
    raw = listing["ChannelInfoList"]
    non_matching = [c["ChannelName"] for c in raw if not c["ChannelName"].startswith(name)]
    assert not non_matching, (
        f"ChannelNameCondition BEGINS_WITH {name!r} must exclude non-matching channels, "
        f"but the list also returned {non_matching!r}"
    )
    matches = [c for c in raw if c["ChannelName"] == name]
    assert len(matches) == 1, f"expected exactly one match for {name!r}, got {matches!r}"
    assert matches[0]["ChannelARN"] == arn, f"expected ChannelARN {arn!r}, got {matches[0]['ChannelARN']!r}"
    assert matches[0]["ChannelType"] == "SINGLE_MASTER", (
        f"expected ChannelType 'SINGLE_MASTER', got {matches[0]['ChannelType']!r}"
    )


def _wait_channel_status(ctx, name, target_status, timeout_s=60.0, interval_s=1.5):
    kv = ctx.client("kinesisvideo")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        info = kv.describe_signaling_channel(ChannelName=name)["ChannelInfo"]
        last = info.get("ChannelStatus")
        if last == target_status:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"channel {name!r} did not reach status {target_status!r}; last seen {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
