"""get-ice-server-config-deleted-channel-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-ice-server-config-deleted-channel-not-found"
GROUP = "state"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetIceServerConfig returns ICE servers for an ACTIVE channel, and after the channel is deleted the
    same call fails with ResourceNotFoundException "<name> channel does not exist !"."""
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-del2-")
    arn = kv.create_signaling_channel(
        ChannelName=name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["ChannelARN"]
    deleted = {"done": False}
    ctx.on_cleanup(lambda: None if deleted["done"] else kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")

    https_endpoint = _get_endpoint(ctx, arn, "HTTPS", "VIEWER")
    sig = ctx.client("kinesis-video-signaling", endpoint_url=https_endpoint)

    # positive control: works while the channel is alive
    ok = sig.get_ice_server_config(ChannelARN=arn)
    assert len(ok["IceServerList"]) > 0, f"expected >=1 ICE server for live channel {arn}, got {ok['IceServerList']!r}"

    # break it
    kv.delete_signaling_channel(ChannelARN=arn)
    deleted["done"] = True
    _wait_channel_gone(ctx, name)

    # effect absent: the very same call now fails, it does not keep succeeding
    code, message = _error(lambda: sig.get_ice_server_config(ChannelARN=arn))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException for deleted channel {arn}, got {code!r}"
    assert message == f"{name} channel does not exist !", f"GetIceServerConfig message: {message!r}"


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


def _wait_channel_gone(ctx, name, timeout_s=60.0, interval_s=1.5):
    from botocore.exceptions import ClientError

    kv = ctx.client("kinesisvideo")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            kv.describe_signaling_channel(ChannelName=name)
            last_code = None
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "ResourceNotFoundException":
                return
        time.sleep(interval_s)
    raise AssertionError(f"channel {name!r} was not removed within {timeout_s}s (last code {last_code!r})")


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
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
