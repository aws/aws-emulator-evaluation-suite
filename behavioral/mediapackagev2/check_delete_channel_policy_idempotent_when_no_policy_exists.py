"""delete-channel-policy-idempotent-when-no-policy-exists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-channel-policy-idempotent-when-no-policy-exists"
GROUP = "policy"
SERVICES = ["mediapackagev2"]


_POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteChannelPolicy on a channel that never had a policy succeeds, and GetChannelPolicy then fails
    ResourceNotFoundException with the exact message; deleting an attached policy also succeeds and removes
    it."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    resource_tags = {"sim2real-audit": "check-create-channel-resource-not-found-missing-group"}
    mp.create_channel_group(ChannelGroupName=group, Tags=resource_tags)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags=resource_tags)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))

    # Idempotent no-op: a ClientError here propagates and fails the check.
    mp.delete_channel_policy(ChannelGroupName=group, ChannelName=channel)

    err_after = _error(
        lambda: mp.get_channel_policy(ChannelGroupName=group, ChannelName=channel)
    )
    assert err_after["Code"] == "ResourceNotFoundException", (
        f"expected GetChannelPolicy to still report no policy after the idempotent "
        f"no-op delete, got {err_after!r}"
    )
    assert err_after["Message"] == _POLICY_NOT_FOUND, f"got {err_after!r}"

    # Positive control: deleting a policy that actually exists also succeeds.
    import json

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    real_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountIngest",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "mediapackagev2:PutObject",
                "Resource": f"arn:aws:mediapackagev2:{ctx.region}:{account_id}:channelGroup/{group}/channel/{channel}",
            }
        ],
    }
    mp.put_channel_policy(
        ChannelGroupName=group,
        ChannelName=channel,
        Policy=json.dumps(real_policy_doc),
    )
    fetched = json.loads(
        mp.get_channel_policy(ChannelGroupName=group, ChannelName=channel)["Policy"]
    )
    assert fetched == real_policy_doc, (
        f"expected the attached policy to round-trip verbatim, got {fetched!r}"
    )
    mp.delete_channel_policy(ChannelGroupName=group, ChannelName=channel)
    err_final = _error(
        lambda: mp.get_channel_policy(ChannelGroupName=group, ChannelName=channel)
    )
    assert err_final["Code"] == "ResourceNotFoundException", (
        f"expected GetChannelPolicy to report ResourceNotFoundException after deleting "
        f"the real policy (positive control), got {err_final!r}"
    )
    assert err_final["Message"] == _POLICY_NOT_FOUND, f"got {err_final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
