"""put-origin-endpoint-policy-invalid-policy-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-origin-endpoint-policy-invalid-policy-rejected"
GROUP = "error-semantics"
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
    """Call fn(); return its ClientError. An unexpected SUCCESS raises, because an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutOriginEndpointPolicy with a malformed (non-JSON) policy document is rejected
    with ValidationException, no policy is attached (GetOriginEndpointPolicy still 404s),
    and attaching a well-formed policy afterward succeeds (positive control)."""
    mp = ctx.client("mediapackagev2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    endpoint = ctx.unique_name("sim2real-mpkg-oe-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))
    created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"purpose": "behavioral"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )

    err = _client_error(
        lambda: mp.put_origin_endpoint_policy(
            ChannelGroupName=group,
            ChannelName=channel,
            OriginEndpointName=endpoint,
            Policy="{this is not valid json",
        )
    )
    code = err.response["Error"]["Code"]
    assert code == "ValidationException", f"expected ValidationException for malformed policy, got {code!r}"
    message = err.response["Error"]["Message"]
    assert message == INVALID_POLICY, f"expected message {INVALID_POLICY!r}, got {message!r}"

    err_after = _client_error(
        lambda: mp.get_origin_endpoint_policy(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
        )
    )
    code_after = err_after.response["Error"]["Code"]
    assert code_after == "ResourceNotFoundException", (
        f"malformed policy must not attach: expected ResourceNotFoundException, got {code_after!r}"
    )
    message_after = err_after.response["Error"]["Message"]
    assert message_after == POLICY_NOT_FOUND, f"expected message {POLICY_NOT_FOUND!r}, got {message_after!r}"

    # Positive control: a well-formed policy is accepted and reflected.
    valid_policy = {
        "Version": "2012-10-17",
        "Id": "MediaPackageOriginEndpointAccessPolicy",
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
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=endpoint,
        Policy=json.dumps(valid_policy),
    )
    got = mp.get_origin_endpoint_policy(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=endpoint
    )
    got_resource = json.loads(got["Policy"])["Statement"][0]["Resource"]
    assert got_resource == created["Arn"], (
        f"expected the well-formed policy to attach and reflect {created['Arn']!r}, got {got_resource!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
