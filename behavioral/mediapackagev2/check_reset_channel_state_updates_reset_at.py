"""reset-channel-state-updates-reset-at."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "reset-channel-state-updates-reset-at"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResetChannelState sets a fresh ResetAt timestamp that a subsequent GetChannel reflects."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real-behav": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real-behav": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    before = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert "ResetAt" not in before or before["ResetAt"] is None, (
        f"expected no ResetAt on a freshly created channel, got {before.get('ResetAt')!r}"
    )

    before_call = datetime.now(timezone.utc)
    mp.reset_channel_state(ChannelGroupName=group_name, ChannelName=channel_name)

    reset_at = _poll_until(
        lambda: mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name).get("ResetAt"),
        predicate=lambda v: v is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    after_read = datetime.now(timezone.utc)
    assert reset_at >= before_call - timedelta(seconds=5), (
        f"expected ResetAt {reset_at!r} to be no earlier than the reset_channel_state call at {before_call!r}"
    )
    assert reset_at <= after_read + timedelta(seconds=5), (
        f"expected ResetAt {reset_at!r} to be no later than the read at {after_read!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
