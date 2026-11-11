"""channel-policy-lifecycle-round-trip."""
from __future__ import annotations

import json
from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "channel-policy-lifecycle-round-trip"
GROUP = "policy"
SERVICES = ["mediapackagev2"]

_POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetChannelPolicy returns the policy PutChannelPolicy attached; after DeleteChannelPolicy, and again
    after a repeated delete, it fails ResourceNotFoundException with the exact message, and the same policy
    can be attached again afterwards."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    created = mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    # MediaPackage channel resource policies govern the data-plane PutObject
    # (ingest) action, not IAM control-plane actions like GetChannel
    # (https://docs.aws.amazon.com/mediapackage/latest/userguide/ingest-auth.html).
    policy_doc = {
        "Version": "2012-10-17",
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
        ChannelGroupName=group_name, ChannelName=channel_name, Policy=json.dumps(policy_doc)
    )

    fetched = mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    assert json.loads(fetched["Policy"]) == policy_doc, "policy round-trip mismatch"

    mp.delete_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)

    err = _client_error(
        lambda: mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    )
    assert err is not None, "expected GetChannelPolicy to fail after DeleteChannelPolicy"
    got_code = err.response["Error"]["Code"]
    assert got_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after delete, got {got_code}"
    )
    assert err.response["Error"]["Message"] == _POLICY_NOT_FOUND, err.response

    # DeleteChannelPolicy is idempotent: deleting an already-absent policy does not
    # error, and the absence it reports remains observable afterward.
    mp.delete_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    redelete_get_err = _client_error(
        lambda: mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    )
    assert redelete_get_err is not None, "expected GetChannelPolicy to still fail after the idempotent re-delete"
    redelete_get_code = redelete_get_err.response["Error"]["Code"]
    assert redelete_get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after idempotent re-delete, got {redelete_get_code}"
    )
    assert redelete_get_err.response["Error"]["Message"] == _POLICY_NOT_FOUND, redelete_get_err.response

    # The identifier is reusable: the identical policy can be reattached afterward.
    mp.put_channel_policy(
        ChannelGroupName=group_name, ChannelName=channel_name, Policy=json.dumps(policy_doc)
    )
    refetched = mp.get_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)
    assert json.loads(refetched["Policy"]) == policy_doc, "reattached policy round-trip mismatch"
    mp.delete_channel_policy(ChannelGroupName=group_name, ChannelName=channel_name)


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
