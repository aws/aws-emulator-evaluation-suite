"""origin-endpoint-policy-lifecycle-put-get-delete."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "origin-endpoint-policy-lifecycle-put-get-delete"
GROUP = "state"
SERVICES = ["mediapackagev2"]

POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


def _expect_error(fn):
    try:
        fn()
    except ClientError as e:
        return e
    raise AssertionError("expected call to raise a ClientError but it succeeded")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutOriginEndpointPolicy attaches a resource policy reflected by GetOriginEndpointPolicy, removed by delete."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real:managed": "true"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    endpoint = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountGetObject",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "mediapackagev2:GetObject",
                "Resource": endpoint["Arn"],
            }
        ],
    }
    mp.put_origin_endpoint_policy(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name, Policy=json.dumps(policy)
    )

    fetched = mp.get_origin_endpoint_policy(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    fetched_policy = json.loads(fetched["Policy"])
    assert fetched_policy == policy, f"expected {policy!r} round-tripped verbatim, got {fetched_policy!r}"

    mp.delete_origin_endpoint_policy(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )

    get_err = _expect_error(
        lambda: mp.get_origin_endpoint_policy(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )
    get_code = get_err.response["Error"]["Code"]
    assert get_code == "ResourceNotFoundException", (
        f"expected GetOriginEndpointPolicy on a deleted policy to fail with "
        f"ResourceNotFoundException, got {get_code}"
    )
    get_message = get_err.response["Error"]["Message"]
    assert get_message == POLICY_NOT_FOUND, f"expected message {POLICY_NOT_FOUND!r}, got {get_message!r}"

    # DeleteOriginEndpointPolicy is idempotent: deleting an
    # already-absent policy succeeds rather than raising, unlike GetOriginEndpointPolicy.
    second_delete = mp.delete_origin_endpoint_policy(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    assert second_delete["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected a second DeleteOriginEndpointPolicy on an already-deleted policy to be "
        f"idempotent and succeed, got {second_delete['ResponseMetadata']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
