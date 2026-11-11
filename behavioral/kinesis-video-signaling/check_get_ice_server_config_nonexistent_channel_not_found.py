"""get-ice-server-config-nonexistent-channel-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-nonexistent-channel-not-found"
GROUP = "error-semantics"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetIceServerConfig on a well-formed ChannelARN that was never created fails with
    ResourceNotFoundException, while the same call against a real, active channel succeeds
    (positive control, same file, same endpoint)."""
    _, real_arn = _create_active_channel(ctx)
    https_endpoint = _get_endpoint(ctx, real_arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    # positive control
    ok = sig.get_ice_server_config(ChannelARN=real_arn)
    assert len(ok["IceServerList"]) > 0, f"positive control: expected a non-empty IceServerList, got {ok['IceServerList']!r}"

    # a syntactically valid ARN for a channel that was never created
    account_id = real_arn.split(":")[4]
    missing_name = ctx.unique_name("sim2real-missing-")
    bogus_arn = f"arn:aws:kinesisvideo:{ctx.region}:{account_id}:channel/{missing_name}/1"
    err = _error(lambda: sig.get_ice_server_config(ChannelARN=bogus_arn))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created channel, got {err!r}"
    )
    assert err["Message"] == f"{missing_name} channel does not exist !", (
        f"unexpected ResourceNotFoundException message: {err['Message']!r}"
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


def _error(fn):
    """Call fn(); return its botocore ``Error`` member. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
