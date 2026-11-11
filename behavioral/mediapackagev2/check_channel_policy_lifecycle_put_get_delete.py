"""channel-policy-lifecycle-put-get-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-policy-lifecycle-put-get-delete"
GROUP = "state"
SERVICES = ["mediapackagev2"]


_POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutChannelPolicy attaches a resource policy that GetChannelPolicy reflects; DeleteChannelPolicy removes it."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    channel = mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountIngest",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "mediapackagev2:PutObject",
                "Resource": channel["Arn"],
            }
        ],
    }
    mp.put_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name, Policy=json.dumps(policy))

    fetched = mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    fetched_policy = json.loads(fetched["Policy"])
    assert fetched_policy == policy, f"policy round-trip mismatch: expected {policy}, got {fetched_policy}"

    mp.delete_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)

    err = _error(lambda: mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name))
    assert err["Code"] == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {err!r}"
    assert err["Message"] == _POLICY_NOT_FOUND, f"got {err!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
