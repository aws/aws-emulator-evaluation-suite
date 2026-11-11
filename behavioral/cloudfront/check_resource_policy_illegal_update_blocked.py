"""resource-policy-illegal-update-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-illegal-update-blocked"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a VPC origin rejects a document whose Statement Resource names a different
    VPC origin with InvalidArgument and its exact message, attaching nothing, while a document whose
    Resource matches ResourceArn is accepted: a policy is never attached to the wrong resource."""
    cf = ctx.client("cloudfront")
    grant_account = ctx.client("sts").get_caller_identity()["Account"]

    vpc_origin, _etag, _instance_id = _create_vpc_origin(ctx, "sim2real-vpcorigin-upd-")
    vo_id = vpc_origin["Id"]
    vo_arn = vpc_origin["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin_best_effort(ctx, vo_id))

    other_origin, _other_etag, _other_instance_id = _create_vpc_origin(
        ctx, "sim2real-vpcorigin-upd-other-"
    )
    other_id = other_origin["Id"]
    other_arn = other_origin["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin_best_effort(ctx, other_id))

    # Let both origins leave "Deploying" before referencing them in a policy --
    # avoids spurious ServiceUnavailable hiccups against freshly-created state.
    _wait_vpc_origin_settled(ctx, vo_id)
    _wait_vpc_origin_settled(ctx, other_id)

    # Break exactly one thing: the policy's own Resource element points at a
    # DIFFERENT VPC origin than the one named by ResourceArn.
    mismatched_policy = json.dumps(_grant_policy(other_arn, grant_account))
    code, message = _error(
        lambda: cf.put_resource_policy(ResourceArn=vo_arn, PolicyDocument=mismatched_policy)
    )
    assert code == "InvalidArgument", code
    expected = (
        "The specified policy isn't valid (InvalidPolicy). Verify that it's both valid JSON, "
        "and that the ARN specified in the policy is the same ARN in the ResourceARN parameter"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no policy was attached to vo_arn by the rejected call.
    # A VPC origin ARN that has
    # NEVER had a policy attached answers GetResourcePolicy with 200 and an
    # EMPTY PolicyDocument -- EntityNotFound is reserved for a policy that
    # existed and was then deleted, which is not this case.
    absent = _get_resource_policy_retry(cf, vo_arn)
    assert json.loads(absent["PolicyDocument"]) == {}, absent["PolicyDocument"]

    # Positive control: the identical operation, same file, with a document
    # whose Resource actually matches ResourceArn is accepted.
    matching_policy = json.dumps(_grant_policy(vo_arn, grant_account))
    cf.put_resource_policy(ResourceArn=vo_arn, PolicyDocument=matching_policy)
    stored = json.loads(cf.get_resource_policy(ResourceArn=vo_arn)["PolicyDocument"])
    assert stored["Statement"][0]["Resource"] == vo_arn, stored


# ===== helpers =====


def _error(fn, retries: int = 3, delay_s: float = 5.0):
    """Invoke ``fn`` (a zero-arg call wrapping one boto3 call) and return the
    error (code, message) on ClientError. Raises on unexpected success -- an
    over-permissive target must not report acceptance as a code mismatch.
    Transparently retries a transient ServiceUnavailable a few times --
    that's AWS-side flakiness on a freshly-created VPC origin, not the
    boundary this check is testing."""
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            result = fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ServiceUnavailable" and attempt < retries - 1:
                time.sleep(delay_s)
                continue
            return code, err.response["Error"].get("Message")
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED: {result!r}")


def _get_resource_policy_retry(cf, resource_arn: str, retries: int = 3, delay_s: float = 5.0):
    """GetResourcePolicy, transparently retrying a transient ServiceUnavailable a few
    times -- the same freshly-created-VPC-origin flakiness _error absorbs."""
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return cf.get_resource_policy(ResourceArn=resource_arn)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ServiceUnavailable" and attempt < retries - 1:
                time.sleep(delay_s)
                continue
            raise


def _grant_policy(
    resource_arn: str, principal_account: str, actions: list[str] | None = None
) -> dict[str, Any]:
    """A minimal resource-policy grant. The principal must be a REAL AWS account:
    CloudFront rejects a policy whose
    Principal names an account that doesn't exist with InvalidArgument ("references
    a principal that doesn't exist"), the well-known docs placeholder
    123456789012 among them -- so callers pass the check's own caller identity."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Sim2RealGrant",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account}:root"},
                "Action": actions or ["cloudfront:GetVpcOrigin"],
                "Resource": resource_arn,
            }
        ],
    }


def _backing_ec2_instance_arn(ctx) -> tuple[str, str]:
    """Launches a minimal, real EC2 instance to back a VPC origin.

    CreateVpcOrigin validates its target ARN synchronously against EC2 (a
    fabricated, syntactically-valid instance ID comes back
    `InvalidInstanceID.Malformed`, discovered empirically) -- so exercising
    PutResourcePolicy's one currently-supported resource type genuinely
    requires a live instance behind it, not just a well-formed ARN. Returns
    ``(arn, instance_id)``; the caller registers termination of
    ``instance_id`` as its own cleanup, run AFTER the VPC origin is deleted.
    """
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": ctx.unique_name("sim2real-vpcorigin-backing-")}
                ],
            }
        ],
        SubnetId=ctx.network().subnet_ids[0],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
    return arn, instance_id


def _terminate_instance(ctx, instance_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise


def _create_vpc_origin(ctx, name_prefix: str) -> tuple[dict[str, Any], str, str]:
    cf = ctx.client("cloudfront")
    arn, instance_id = _backing_ec2_instance_arn(ctx)
    ctx.on_cleanup(lambda: _terminate_instance(ctx, instance_id))
    config = {
        "Name": ctx.unique_name(name_prefix),
        "Arn": arn,
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "https-only",
    }
    created = cf.create_vpc_origin(VpcOriginEndpointConfig=config)
    return created["VpcOrigin"], created["ETag"], instance_id


def _wait_vpc_origin_settled(
    ctx, vo_id: str, timeout_s: float = 900.0, interval_s: float = 15.0
) -> dict[str, Any]:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    resp: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cf.get_vpc_origin(Id=vo_id)
        last = resp["VpcOrigin"]["Status"]
        if last != "Deploying":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vo_id} never left Deploying (last={last!r})")


def _delete_vpc_origin_best_effort(ctx, vo_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        resp = _wait_vpc_origin_settled(ctx, vo_id)
        etag = resp["ETag"]
    except Exception:
        try:
            etag = cf.get_vpc_origin(Id=vo_id)["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
    try:
        cf.delete_vpc_origin(Id=vo_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
