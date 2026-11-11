"""put-channel-policy-resource-not-found-missing-channel."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-channel-policy-resource-not-found-missing-channel"
GROUP = "error-semantics"
SERVICES = ["mediapackagev2"]


CHANNEL_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your channel. "
    "Verify your channel name or add a channel and then try again"
)


POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected success raises, so a target that
    accepts a call real AWS refuses cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutChannelPolicy on a ChannelName absent from a real channel group fails ResourceNotFoundException
    with the exact message and leaves no policy for that name, while the same policy attached to a real
    channel is returned by GetChannelPolicy."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-mpkg-cg-")
    mp.create_channel_group(ChannelGroupName=group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))

    missing_channel = ctx.unique_name("sim2real-mpkg-ch-missing-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "mediapackagev2:GetChannel",
                "Resource": "*",
            }
        ],
    }
    err = _client_error(
        lambda: mp.put_channel_policy(
            ChannelGroupName=group,
            ChannelName=missing_channel,
            Policy=json.dumps(policy_doc),
        )
    )
    code = err.response["Error"]["Code"]
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for PutChannelPolicy against a missing "
        f"channel, got {code!r}"
    )
    message = err.response["Error"]["Message"]
    assert message == CHANNEL_NOT_FOUND, f"expected message {CHANNEL_NOT_FOUND!r}, got {message!r}"

    # The rejected PutChannelPolicy must not have left a policy record behind: creating
    # a channel with the exact name just rejected must start with no attached policy.
    mp.create_channel(ChannelGroupName=group, ChannelName=missing_channel)
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=missing_channel)
    )
    reused_err = _client_error(
        lambda: mp.get_channel_policy(ChannelGroupName=group, ChannelName=missing_channel)
    )
    reused_code = reused_err.response["Error"]["Code"]
    assert reused_code == "ResourceNotFoundException", (
        f"expected the earlier rejected PutChannelPolicy to have left no policy behind, "
        f"but GetChannelPolicy on the newly created same-named channel returned "
        f"{reused_code!r} instead of ResourceNotFoundException"
    )
    reused_message = reused_err.response["Error"]["Message"]
    assert reused_message == POLICY_NOT_FOUND, f"expected message {POLICY_NOT_FOUND!r}, got {reused_message!r}"

    # Positive control: a real channel accepts the identical policy document.
    real_channel = ctx.unique_name("sim2real-mpkg-ch-real-")
    created_channel = mp.create_channel(ChannelGroupName=group, ChannelName=real_channel)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=real_channel))
    real_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountIngest",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "mediapackagev2:PutObject",
                "Resource": created_channel["Arn"],
            }
        ],
    }
    mp.put_channel_policy(
        ChannelGroupName=group, ChannelName=real_channel, Policy=json.dumps(real_policy_doc)
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel_policy(ChannelGroupName=group, ChannelName=real_channel)
    )
    got = mp.get_channel_policy(ChannelGroupName=group, ChannelName=real_channel)
    got_policy = json.loads(got["Policy"])
    assert got_policy == real_policy_doc, (
        f"expected GetChannelPolicy to echo the attached policy verbatim, "
        f"expected {real_policy_doc!r}, got {got_policy!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
