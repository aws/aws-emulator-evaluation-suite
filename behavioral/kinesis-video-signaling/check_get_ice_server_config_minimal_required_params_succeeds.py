"""get-ice-server-config-minimal-required-params-succeeds."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-minimal-required-params-succeeds"
GROUP = "data-plane"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetIceServerConfig with only ChannelARN set returns ICE servers with Ttl 300, turn/turns/stun URIs
    (at least one TURN), and non-empty Username and Password."""
    _, arn = _create_active_channel(ctx)
    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    resp = sig.get_ice_server_config(ChannelARN=arn)
    servers = resp["IceServerList"]
    assert len(servers) > 0, "expected at least one ICE server entry with only ChannelARN set"

    saw_turn_scheme = False
    for server in servers:
        assert server["Ttl"] == 300, f"expected fixed TTL of 300s, got {server['Ttl']}"
        uris = server["Uris"]
        assert len(uris) > 0, f"expected at least one URI on ICE server entry, got {server!r}"
        for uri in uris:
            scheme = uri.split(":", 1)[0]
            assert scheme in ("turn", "turns", "stun"), f"unexpected ICE URI scheme: {uri!r}"
            if scheme in ("turn", "turns"):
                saw_turn_scheme = True
        assert server["Username"], "expected a non-empty Username even without ClientId set"
        assert server["Password"], "expected a non-empty Password even without ClientId set"
    assert saw_turn_scheme, "expected at least one turn:/turns: URI among the returned ICE servers"


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
    kwargs = {"ChannelName": name, "ChannelType": channel_type}
    if ttl_seconds is not None:
        kwargs["SingleMasterConfiguration"] = {"MessageTtlSeconds": ttl_seconds}
    arn = kv.create_signaling_channel(Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs)["ChannelARN"]
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
