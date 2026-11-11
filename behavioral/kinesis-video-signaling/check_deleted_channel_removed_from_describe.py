"""deleted-channel-removed-from-describe."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleted-channel-removed-from-describe"
GROUP = "state"
SERVICES = ["kinesis-video-signaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After DeleteSignalingChannel, DescribeSignalingChannel for the name and a second delete of the ARN
    both fail with ResourceNotFoundException and the same exact message."""
    kv = ctx.client("kinesisvideo")
    name = ctx.unique_name("sim2real-kvsig-del-")
    arn = kv.create_signaling_channel(
        ChannelName=name,
        ChannelType="SINGLE_MASTER",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["ChannelARN"]
    deleted = {"done": False}
    ctx.on_cleanup(lambda: None if deleted["done"] else kv.delete_signaling_channel(ChannelARN=arn))
    _wait_channel_status(ctx, name, "ACTIVE")

    kv.delete_signaling_channel(ChannelARN=arn)
    deleted["done"] = True
    _wait_channel_gone(ctx, name)

    not_found = "The requested channel is not found or not active."
    err = _error(lambda: kv.describe_signaling_channel(ChannelName=name))
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from DescribeSignalingChannel on deleted channel "
        f"{name!r}, got {err!r}"
    )
    assert err["Message"] == not_found, f"unexpected DescribeSignalingChannel message: {err['Message']!r}"

    dup_err = _error(lambda: kv.delete_signaling_channel(ChannelARN=arn))
    assert dup_err["Code"] == "ResourceNotFoundException", (
        f"expected a second DeleteSignalingChannel on the already-deleted ARN {arn!r} to fail "
        f"with ResourceNotFoundException -- proving the dead ARN is unusable, not merely absent "
        f"from describe -- got {dup_err!r}"
    )
    assert dup_err["Message"] == not_found, (
        f"unexpected DeleteSignalingChannel message: {dup_err['Message']!r}"
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


def _wait_channel_gone(ctx, name, timeout_s=60.0, interval_s=1.5):
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


def _error(fn):
    """The ClientError's ``Error`` member; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
