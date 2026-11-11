"""get-ice-server-config-returns-valid-turn-credentials."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-returns-valid-turn-credentials"
GROUP = "data-plane"
SERVICES = ["kinesis-video-signaling"]

_CRED_PATTERN = re.compile(r"^[A-Za-z0-9+/=_.:-]+$")


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetIceServerConfig on an ACTIVE channel returns ICE servers with Ttl 300, turn/turns/stun URIs (at least one
    TURN), a Username of the form "<unix-timestamp>:<token>" whose timestamp lies within 600 s after the call,
    and a non-empty Password."""
    _, arn = _create_active_channel(ctx)
    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    before = int(time.time())
    resp = sig.get_ice_server_config(ChannelARN=arn, ClientId=ctx.unique_name("viewer-"))
    servers = resp["IceServerList"]
    assert len(servers) > 0, "expected at least one ICE server entry"

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
        username = server["Username"]
        assert _CRED_PATTERN.match(username), username
        assert ":" in username, f"expected '<timestamp>:<token>' Username shape, got {username!r}"
        ts_part = username.split(":", 1)[0]
        assert ts_part.isdigit(), f"expected a leading unix-timestamp in Username, got {username!r}"
        # the embedded timestamp is the credential expiry: it must be in the future, on the
        # order of the 300s Ttl (allow slack for clock skew / rounding)
        assert before <= int(ts_part) <= before + 600, (
            f"embedded credential timestamp {ts_part} not within expected window of now={before}"
        )
        assert _CRED_PATTERN.match(server["Password"]) and len(server["Password"]) > 0, server["Password"]
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
