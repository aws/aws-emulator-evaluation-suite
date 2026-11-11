"""get-channel-policy-not-found-when-never-attached."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-channel-policy-not-found-when-never-attached"
GROUP = "error-semantics"
SERVICES = ["mediapackagev2"]


_POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetChannelPolicy on a freshly created Channel that never had PutChannelPolicy
    called on it returns ResourceNotFoundException, and attaching a policy (positive
    control) makes the very next GetChannelPolicy call succeed."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    mp.create_channel_group(ChannelGroupName=group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    created = mp.create_channel(ChannelGroupName=group, ChannelName=channel)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))

    err = _error(
        lambda: mp.get_channel_policy(ChannelGroupName=group, ChannelName=channel)
    )
    assert err["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException on a never-attached policy, got {err!r}"
    )
    assert err["Message"] == _POLICY_NOT_FOUND, f"got {err!r}"

    # Positive control: attaching a policy makes GetChannelPolicy succeed immediately,
    # and echo the exact document back (not just something truthy).
    policy_doc = {
        "Version": "2012-10-17",
        "Id": "MediaPackageChannelIngestPolicy",
        "Statement": [
            {
                "Sid": "AllowCrossAccountIngest",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "mediapackagev2:PutObject",
                "Resource": created["Arn"],
            }
        ],
    }
    mp.put_channel_policy(
        ChannelGroupName=group,
        ChannelName=channel,
        Policy=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel_policy(ChannelGroupName=group, ChannelName=channel)
    )
    got = mp.get_channel_policy(ChannelGroupName=group, ChannelName=channel)
    fetched_doc = json.loads(got["Policy"])
    assert fetched_doc == policy_doc, (
        f"expected GetChannelPolicy to echo the attached document verbatim, "
        f"expected {policy_doc!r}, got {fetched_doc!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
