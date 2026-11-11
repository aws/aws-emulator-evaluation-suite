"""put-channel-policy-invalid-json-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-channel-policy-invalid-json-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

INVALID_POLICY = (
    "Validation error encountered at request.policy: The policy you entered isn't valid. "
    "The policy must be a valid IAM policy. Check your policy and then try again"
)
POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutChannelPolicy with malformed policy JSON is rejected and no policy is attached."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    channel = mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    err = _client_error(
        lambda: mp.put_channel_policy(
            ChannelGroupName=group_name, ChannelName=channel_name, Policy="{this is not valid json"
        )
    )
    code = err.response["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    message = err.response["Error"]["Message"]
    assert message == INVALID_POLICY, f"expected message {INVALID_POLICY!r}, got {message!r}"

    # Effect absent: no policy got attached.
    not_found_err = _client_error(
        lambda: mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    )
    not_found_code = not_found_err.response["Error"]["Code"]
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code!r}"
    )
    not_found_message = not_found_err.response["Error"]["Message"]
    assert not_found_message == POLICY_NOT_FOUND, f"expected message {POLICY_NOT_FOUND!r}, got {not_found_message!r}"

    # Positive control: a well-formed policy is accepted and readable back.
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
    ctx.on_cleanup(lambda: mp.delete_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name))
    fetched = mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    fetched_resource = json.loads(fetched["Policy"])["Statement"][0]["Resource"]
    assert fetched_resource == channel["Arn"], (
        f"expected policy Resource {channel['Arn']!r}, got {fetched_resource!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
