"""get-ice-server-config-concurrent-clients-share-time-bucketed-credential."""
from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "get-ice-server-config-concurrent-clients-share-time-bucketed-credential"
GROUP = "concurrency"
SERVICES = ["kinesis-video-signaling"]

_CRED_PATTERN = re.compile(r"^[A-Za-z0-9+/=_.:-]+$")
_BURSTS = 2


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent GetIceServerConfig calls with distinct ClientIds all succeed with servers of Ttl 300 and
    non-empty Uris, and share one "<timestamp>:<token>" username, the channel's time-bucketed TURN
    credential."""
    _, arn = _create_active_channel(ctx)
    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    racer_count = 8

    def _call(i):
        client_id = f"{ctx.unique_name('racer-')}-{i}"
        resp = sig.get_ice_server_config(ChannelARN=arn, ClientId=client_id)
        servers = resp["IceServerList"]
        assert len(servers) > 0, f"expected at least one ICE server entry, got {servers!r}"
        server = servers[0]
        assert server["Ttl"] == 300, f"expected fixed TTL of 300s, got {server['Ttl']}"
        assert len(server["Uris"]) > 0, f"expected at least one URI, got {server['Uris']!r}"
        return server["Username"], server["Password"]

    # The username's time bucket rolls over on the wall clock, so a burst that straddles a bucket
    # boundary sees two; the burst is repeated, and a second straddle in a row cannot happen.
    for _ in range(_BURSTS):
        with ThreadPoolExecutor(max_workers=racer_count) as pool:
            results = list(pool.map(_call, range(racer_count)))

        assert len(results) == racer_count, "one or more concurrent calls raised instead of succeeding"

        usernames = {u for u, _ in results}
        passwords = {p for _, p in results}
        if len(usernames) == 1:
            break
    # every concurrent call against the SAME channel within the same short window is handed
    # the identical channel-scoped Username (it encodes an expiry timestamp + the channel
    # ARN, not the caller's ClientId) -- this is real, empirically-observed behavior, so
    # concurrency must converge on ONE shared username, not `racer_count` distinct ones.
    # The Password, however, is independently derived per call (it varies even when the
    # Username is identical), so we only assert its shape, not its equality.
    assert len(usernames) == 1, f"expected one shared credential username under concurrency, got {usernames}"
    shared_username = next(iter(usernames))
    assert ":" in shared_username, f"expected '<timestamp>:<token>' Username shape, got {shared_username!r}"
    ts_part = shared_username.split(":", 1)[0]
    assert ts_part.isdigit(), f"expected leading unix-timestamp in shared Username, got {shared_username!r}"
    for pw in passwords:
        assert _CRED_PATTERN.match(pw) and len(pw) > 0, f"malformed or empty Password: {pw!r}"


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
    arn = kv.create_signaling_channel(Tags=[{"Key": "sim2real-check", "Value": CHECK}], **kwargs)[
        "ChannelARN"
    ]
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
