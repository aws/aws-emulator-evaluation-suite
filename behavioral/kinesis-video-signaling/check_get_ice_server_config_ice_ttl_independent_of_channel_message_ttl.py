"""get-ice-server-config-ice-ttl-independent-of-channel-message-ttl."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-ice-ttl-independent-of-channel-message-ttl"
GROUP = "data-plane"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetIceServerConfig returns Ttl 300 and at least one URI even on a channel whose MessageTtlSeconds is set to
    the 5 s minimum: the channel's message TTL is a separate setting from the ICE credential TTL."""
    short_message_ttl = 5
    _, arn = _create_active_channel(ctx, ttl_seconds=short_message_ttl)

    kv = ctx.client("kinesisvideo")
    info = kv.describe_signaling_channel(ChannelARN=arn)["ChannelInfo"]
    assert info["SingleMasterConfiguration"]["MessageTtlSeconds"] == short_message_ttl

    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    resp = sig.get_ice_server_config(ChannelARN=arn, ClientId=ctx.unique_name("peer-"))
    servers = resp["IceServerList"]
    assert len(servers) > 0, "expected at least one ICE server entry"
    for server in servers:
        assert server["Ttl"] == 300, (
            f"expected the ICE credential Ttl to stay fixed at 300s regardless of the "
            f"channel's {short_message_ttl}s MessageTtlSeconds, got {server['Ttl']}"
        )
        assert len(server["Uris"]) > 0, f"expected at least one URI on ICE server entry, got {server!r}"


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


def _create_active_channel(ctx, channel_type="SINGLE_MASTER", ttl_seconds=None):
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-")
    kwargs = {"ChannelName": name, "ChannelType": channel_type, "Tags": [{"Key": "sim2real", "Value": CHECK}]}
    if ttl_seconds is not None:
        kwargs["SingleMasterConfiguration"] = {"MessageTtlSeconds": ttl_seconds}
    arn = kv.create_signaling_channel(**kwargs)["ChannelARN"]
    ctx.on_cleanup(lambda: kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")
    return name, arn


def _get_endpoint(ctx, channel_arn, protocol, role):
    kv = ctx.client("kinesisvideo")
    resp = kv.get_signaling_channel_endpoint(
        ChannelARN=channel_arn,
        SingleMasterChannelEndpointConfiguration={"Protocols": [protocol], "Role": role},
    )
    for entry in resp["ResourceEndpointList"]:
        if entry["Protocol"] == protocol:
            return entry["ResourceEndpoint"]
    raise AssertionError(f"no {protocol} endpoint returned for channel {channel_arn}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
