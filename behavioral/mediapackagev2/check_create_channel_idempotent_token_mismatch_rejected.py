"""create-channel-idempotent-token-mismatch-rejected."""
from __future__ import annotations

from typing import Any, Callable, Optional

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-idempotent-token-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


def _client_error(fn: Callable[[], Any]) -> Optional[ClientError]:
    try:
        fn()
        return None
    except ClientError as e:
        return e


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying CreateChannel with the same ClientToken and parameters returns the same Arn; the same token
    with a different Description fails ConflictException IDEMPOTENT_PARAMETER_MISMATCH with the exact
    message, and the channel's Description stays 'original'."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    other_channel_name = ctx.unique_name("sim2real-mpv2-ch2-")
    token = ctx.unique_name("sim2real-mpv2-tok-")

    mp.create_channel_group(ChannelGroupName=group_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    first = mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, ClientToken=token, Description="original"
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    # Positive control: identical replay (same name, token, params) is idempotent.
    replay = mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, ClientToken=token, Description="original"
    )
    assert replay["Arn"] == first["Arn"], f"idempotent replay changed Arn: {replay['Arn']!r} != {first['Arn']!r}"
    assert replay["Description"] == "original", f"idempotent replay changed Description: {replay['Description']!r}"

    # Break: same name + token, different Description.
    err = _client_error(
        lambda: mp.create_channel(
            ChannelGroupName=group_name, ChannelName=channel_name, ClientToken=token, Description="different"
        )
    )
    assert err is not None, "expected idempotency-token param mismatch to fail, but the call succeeded"
    assert err.response["Error"]["Code"] == "ConflictException", (
        f"expected ConflictException, got {err.response['Error']['Code']!r}"
    )
    expected_message = (
        "You've specified a client token with your request using parameter values that differ "
        "from a previous request that used the same client token. Check your parameters and "
        "then try again"
    )
    assert err.response["Error"]["Message"] == expected_message, err.response
    assert err.response.get("ConflictExceptionType") == "IDEMPOTENT_PARAMETER_MISMATCH", (
        f"expected ConflictExceptionType=IDEMPOTENT_PARAMETER_MISMATCH, got "
        f"{err.response.get('ConflictExceptionType')!r} (must be distinguishable from a "
        f"duplicate-name RESOURCE_ALREADY_EXISTS conflict on the same API)"
    )

    # Effect absent: the channel still has its original description, not the mismatched retry's.
    unchanged = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert unchanged["Description"] == "original", f"Description leaked through as {unchanged['Description']!r}"

    # Positive control: the operation still works for a fresh channel/token pair.
    mp.create_channel(ChannelGroupName=group_name, ChannelName=other_channel_name)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=other_channel_name))
    ok = mp.get_channel(ChannelGroupName=group_name, ChannelName=other_channel_name)
    assert ok["ChannelName"] == other_channel_name, f"expected {other_channel_name!r}, got {ok['ChannelName']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
