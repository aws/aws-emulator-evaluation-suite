"""get-ice-server-config-client-id-pattern-not-enforced."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-client-id-pattern-not-enforced"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetIceServerConfig returns a non-empty ICE server list both for a conforming ClientId and for one
    with characters outside the modeled pattern, which AWS does not enforce server-side."""
    _, arn = _create_active_channel(ctx)
    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    # positive control: a pattern-conforming ClientId succeeds
    ok = sig.get_ice_server_config(ChannelARN=arn, ClientId="valid-client-id-1")
    assert len(ok["IceServerList"]) > 0

    # violates the modeled pattern (space, "!") but stays within the 1..256 length bound, so
    # botocore's client-side validator (which enforces min/max but not pattern) lets this
    # reach the wire; real AWS accepts it -- if this raises, the target is stricter than AWS
    malformed = sig.get_ice_server_config(ChannelARN=arn, ClientId="not a valid client id!")
    assert len(malformed["IceServerList"]) > 0, (
        f"expected the pattern-violating ClientId to be accepted exactly like the conforming "
        f"one (real AWS does not enforce this pattern), got IceServerList="
        f"{malformed.get('IceServerList')!r}"
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


def _create_active_channel(ctx, channel_type="SINGLE_MASTER", ttl_seconds=None):
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-")
    kwargs = {"ChannelName": name, "ChannelType": channel_type}
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
