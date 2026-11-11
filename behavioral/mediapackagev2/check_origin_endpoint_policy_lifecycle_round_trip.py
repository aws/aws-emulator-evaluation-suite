"""origin-endpoint-policy-lifecycle-round-trip."""
from __future__ import annotations

import json
from typing import Any, Callable, Optional

from behavioral_harness import tags

CHECK = "origin-endpoint-policy-lifecycle-round-trip"
GROUP = "policy"
SERVICES = ["mediapackagev2"]

POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutOriginEndpointPolicy attaches a resource policy that GetOriginEndpointPolicy
    echoes back verbatim; DeleteOriginEndpointPolicy removes it so a subsequent
    GetOriginEndpointPolicy fails with ResourceNotFoundException."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"purpose": "behavioral"}
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")
    created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
        Tags={"purpose": "behavioral"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )

    # Origin endpoint resource policies govern the data-plane GetObject/HarvestObject
    # actions, not IAM control-plane actions like GetOriginEndpoint
    # (https://docs.aws.amazon.com/mediapackage/latest/userguide/endpoint-auth.html).
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountGetObject",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "mediapackagev2:GetObject",
                "Resource": created["Arn"],
            }
        ],
    }
    mp.put_origin_endpoint_policy(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        Policy=json.dumps(policy_doc),
    )

    fetched = mp.get_origin_endpoint_policy(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    fetched_policy = json.loads(fetched["Policy"])
    assert fetched_policy == policy_doc, (
        f"policy round-trip mismatch: expected {policy_doc!r}, got {fetched_policy!r}"
    )

    mp.delete_origin_endpoint_policy(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )

    err = _client_error(
        lambda: mp.get_origin_endpoint_policy(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=endpoint_name,
        )
    )
    assert err is not None, "expected GetOriginEndpointPolicy to fail after delete"
    got_code = err.response["Error"]["Code"]
    assert got_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException after policy delete, got {got_code!r}"
    )
    got_message = err.response["Error"]["Message"]
    assert got_message == POLICY_NOT_FOUND, f"expected message {POLICY_NOT_FOUND!r}, got {got_message!r}"


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
