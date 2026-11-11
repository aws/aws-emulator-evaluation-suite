"""get-ice-server-config-malformed-channel-arn-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-malformed-channel-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetIceServerConfig rejects a ChannelARN that fails the ARN pattern with InvalidArgumentException and the
    exact message "Invalid Channel ARN !", while the well-formed ARN of the same channel returns ICE servers."""
    _, arn = _create_active_channel(ctx)
    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    # positive control
    ok = sig.get_ice_server_config(ChannelARN=arn)
    assert len(ok["IceServerList"]) > 0, f"positive control returned no ICE servers: {ok!r}"

    # the pattern requires the ARN to end in a numeric version segment; appending a letter
    # breaks that requirement while keeping the string within the length constraint
    malformed_arn = arn + "x"
    err = _error(lambda: sig.get_ice_server_config(ChannelARN=malformed_arn))
    assert err["Code"] == "InvalidArgumentException", f"expected InvalidArgumentException, got {err!r}"
    assert err["Message"] == "Invalid Channel ARN !", (
        f"unexpected InvalidArgumentException message: {err['Message']!r}"
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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
