"""delete-origin-endpoint-policy-idempotent-when-no-policy-exists."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "delete-origin-endpoint-policy-idempotent-when-no-policy-exists"
GROUP = "policy"
SERVICES = ["mediapackagev2"]


POLICY_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your policy. "
    "Attach a policy to your resource and then try again"
)


def _client_error(fn):
    """Call fn(); return its ClientError. An unexpected success raises, so a target that
    answers a lookup real AWS refuses cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteOriginEndpointPolicy on an endpoint that never had a policy succeeds, and
    GetOriginEndpointPolicy then fails ResourceNotFoundException with the exact message; deleting an
    attached policy also succeeds and removes it."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    endpoint = ctx.unique_name("sim2real-mpkg-oe-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))
    endpoint_created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )

    # The no-op delete must succeed: a ClientError here fails the check.
    mp.delete_origin_endpoint_policy(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )

    err_after = _client_error(
        lambda: mp.get_origin_endpoint_policy(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )
    code_after = err_after.response["Error"]["Code"]
    assert code_after == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetOriginEndpointPolicy after no-op delete, "
        f"got {code_after}"
    )
    message_after = err_after.response["Error"]["Message"]
    assert message_after == POLICY_NOT_FOUND, (
        f"expected message {POLICY_NOT_FOUND!r}, got {message_after!r}"
    )

    # Positive control: deleting a policy that actually exists also succeeds.
    mp.put_origin_endpoint_policy(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "MediaPackageOriginEndpointAccessPolicy",
                "Statement": [
                    {
                        "Sid": "AllowCrossAccountGetObject",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                        "Action": "mediapackagev2:GetObject",
                        "Resource": endpoint_created["Arn"],
                    }
                ],
            }
        ),
    )
    fetched_policy = mp.get_origin_endpoint_policy(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )["Policy"]
    assert fetched_policy, f"expected a non-empty policy document, got {fetched_policy!r}"
    mp.delete_origin_endpoint_policy(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )
    err_final = _client_error(
        lambda: mp.get_origin_endpoint_policy(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )
    code_final = err_final.response["Error"]["Code"]
    assert code_final == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetOriginEndpointPolicy after real delete, "
        f"got {code_final}"
    )
    message_final = err_final.response["Error"]["Message"]
    assert message_final == POLICY_NOT_FOUND, (
        f"expected message {POLICY_NOT_FOUND!r}, got {message_final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
