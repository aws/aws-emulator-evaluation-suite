"""channel-group-idempotent-token-mismatch-rejected."""
from __future__ import annotations

from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "channel-group-idempotent-token-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Replaying CreateChannelGroup with the same ClientToken and parameters returns the same Arn; the same
    token with a different Description fails ConflictException IDEMPOTENT_PARAMETER_MISMATCH with the exact
    message, and the group's Description stays 'A'."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-idem-")
    token = "sim2real-fixed-token-abc"

    first = mp.create_channel_group(
        ChannelGroupName=group_name,
        ClientToken=token,
        Description="A",
        Tags={"sim2real": "channel-group-idempotent-token-mismatch-rejected"},
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    # positive control: identical replay (same name, token, params) is idempotent
    replay = mp.create_channel_group(
        ChannelGroupName=group_name,
        ClientToken=token,
        Description="A",
        Tags={"sim2real": "channel-group-idempotent-token-mismatch-rejected"},
    )
    assert replay["Arn"] == first["Arn"], (
        f"expected idempotent replay to return the same Arn, got {replay['Arn']!r} vs {first['Arn']!r}"
    )
    assert replay["Description"] == "A", (
        f"expected idempotent replay to echo Description 'A', got {replay['Description']!r}"
    )

    # break: same name + token, different Description
    err = _client_error(
        lambda: mp.create_channel_group(
            ChannelGroupName=group_name,
            ClientToken=token,
            Description="B",
            Tags={"sim2real": "channel-group-idempotent-token-mismatch-rejected"},
        )
    )
    assert err is not None, "expected idempotency-token param mismatch to fail"
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
        f"expected ConflictExceptionType IDEMPOTENT_PARAMETER_MISMATCH, got {err.response.get('ConflictExceptionType')!r}"
    )

    # effect absent: Description still "A"
    still = mp.get_channel_group(ChannelGroupName=group_name)
    assert still["Description"] == "A", f"Description leaked through as {still['Description']!r}"


def _client_error(fn: Callable[[], Any]) -> Optional[Any]:
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as e:
        return e


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
