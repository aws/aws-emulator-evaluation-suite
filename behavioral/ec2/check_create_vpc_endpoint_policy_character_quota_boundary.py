"""create-vpc-endpoint-policy-character-quota-boundary."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vpc-endpoint-policy-character-quota-boundary"
GROUP = "vpc-endpoints"
SERVICES = ["ec2"]

_QUOTA_CHARS = 20480  # Characters per VPC endpoint policy (Service Quotas, not adjustable)
_OVER_LIMIT = ("InvalidPolicyDocument", "Please provide a valid VPC Endpoint policy")


def _policy(target_len: int, *, action: str = "s3:GetObject") -> str:
    """A minimal valid gateway endpoint policy, compact JSON, padded to exactly ``target_len``
    characters with trailing whitespace (which the character quota counts)."""
    doc = {
        "Version": "2008-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": action,
            "Resource": "arn:aws:s3:::*",
        }],
    }
    base = json.dumps(doc, separators=(",", ":"))
    pad = target_len - len(base)
    assert pad >= 0, f"base policy ({len(base)} chars) already exceeds the target {target_len}"
    return base + (" " * pad)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _teardown(fn, *not_found: str):
    """A cleanup running fn() where a failed delete raises; returns on the resource's own not-found."""
    def run_undo() -> None:
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A gateway VPC endpoint policy of exactly 20,480 characters is accepted and round-trips;
    one character more is refused with the fixed, non-adjustable character quota's error, the
    stored policy is left unchanged, and a further update with a valid policy still succeeds.

    Reference: https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html
    """
    ec2 = ctx.client("ec2")
    service_name = f"com.amazonaws.{ctx.region}.s3"
    tag_value = CHECK

    vpc_name = ctx.unique_name("sim2real-behav-vpce-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.92.0.0/28",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "Name", "Value": vpc_name}, {"Key": "sim2real", "Value": tag_value}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc), "InvalidVpcID.NotFound"))

    at_limit = _policy(_QUOTA_CHARS)
    over_limit = _policy(_QUOTA_CHARS + 1)
    assert len(at_limit) == _QUOTA_CHARS, (
        f"constructed policy is {len(at_limit)} chars, wanted {_QUOTA_CHARS}")
    assert len(over_limit) == _QUOTA_CHARS + 1, (
        f"constructed policy is {len(over_limit)} chars, wanted {_QUOTA_CHARS + 1}")

    ep_name = ctx.unique_name("sim2real-behav-vpce-")
    created = ec2.create_vpc_endpoint(
        VpcId=vpc, ServiceName=service_name, VpcEndpointType="Gateway", PolicyDocument=at_limit,
        TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": [
            {"Key": "Name", "Value": ep_name}, {"Key": "sim2real", "Value": tag_value}]}],
    )["VpcEndpoint"]
    endpoint_id = created["VpcEndpointId"]
    ctx.on_cleanup(
        _teardown(lambda: ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint_id]),
                  "InvalidVpcEndpointId.NotFound"))

    got = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert json.loads(got["PolicyDocument"]) == json.loads(at_limit), (
        f"the policy at the 20,480-character quota round-tripped as {got['PolicyDocument']!r}")

    code, message = _error(
        lambda: ec2.modify_vpc_endpoint(VpcEndpointId=endpoint_id, PolicyDocument=over_limit))
    assert (code, message) == _OVER_LIMIT, f"expected {_OVER_LIMIT}, got ({code!r}, {message!r})"

    unchanged = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert json.loads(unchanged["PolicyDocument"]) == json.loads(at_limit), (
        f"a refused update must leave the stored policy untouched; "
        f"it reads {unchanged['PolicyDocument']!r}"
    )

    # Restore: the operation is not broken outright — a valid policy at the same boundary succeeds.
    restored = _policy(_QUOTA_CHARS, action="s3:ListBucket")
    ec2.modify_vpc_endpoint(VpcEndpointId=endpoint_id, PolicyDocument=restored)
    final = ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint_id])["VpcEndpoints"][0]
    assert json.loads(final["PolicyDocument"]) == json.loads(restored), (
        f"a within-quota update after the refusal should take effect; got {final['PolicyDocument']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
