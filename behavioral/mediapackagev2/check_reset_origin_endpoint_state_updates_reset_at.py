"""reset-origin-endpoint-state-updates-reset-at."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "reset-origin-endpoint-state-updates-reset-at"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ResetOriginEndpointState sets a fresh ResetAt timestamp reflected by a subsequent GetOriginEndpoint."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )

    before = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    assert "ResetAt" not in before or before["ResetAt"] is None, (
        f"expected no ResetAt on a freshly created origin endpoint, got {before.get('ResetAt')!r}"
    )

    before_call = datetime.now(timezone.utc)
    mp.reset_origin_endpoint_state(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )

    reset_at = _poll_until(
        lambda: mp.get_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        ).get("ResetAt"),
        predicate=lambda v: v is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert reset_at >= before_call - timedelta(seconds=5), (
        f"expected ResetAt >= {before_call.isoformat()} (call time), got {reset_at.isoformat()}"
    )
    now = datetime.now(timezone.utc)
    assert reset_at <= now + timedelta(seconds=5), (
        f"expected ResetAt <= {now.isoformat()} (read time), got {reset_at.isoformat()}"
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
