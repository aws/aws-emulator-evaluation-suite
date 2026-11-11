"""signaling-channel-reaches-active-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "signaling-channel-reaches-active-state"
GROUP = "state"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created single-primary-peer signaling channel transitions CREATING -> ACTIVE."""
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-")
    resp = kv.create_signaling_channel(
        ChannelName=name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["ChannelARN"]
    ctx.on_cleanup(lambda: kv.delete_signaling_channel(ChannelARN=arn))

    info = _wait_channel_status(ctx, name, "ACTIVE")
    assert info["ChannelStatus"] == "ACTIVE", f"expected ACTIVE, got {info['ChannelStatus']!r}"
    assert info["ChannelType"] == "SINGLE_MASTER", f"expected SINGLE_MASTER, got {info['ChannelType']!r}"
    assert info["ChannelARN"] == arn, f"expected ARN {arn!r}, got {info['ChannelARN']!r}"
    assert info["ChannelName"] == name, f"expected name {name!r}, got {info['ChannelName']!r}"


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
