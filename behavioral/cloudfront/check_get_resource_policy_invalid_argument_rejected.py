"""get-resource-policy-invalid-argument-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-policy-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this ARN, but the call SUCCEEDED and returned {result!r}")


def _code_or_result(fn):
    """Return (error_code, None) on ClientError, or (None, result) on success."""
    try:
        return None, fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], None


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy rejects a malformed ARN with InvalidArgument and a missing VPC origin ARN
    with EntityNotFound, while a real VPC origin with no policy returns an empty PolicyDocument."""
    cf = ctx.client("cloudfront")

    # Structurally invalid: not an ARN at all.
    malformed_arn = "not-an-arn ?? definitely not one"
    malformed_code, malformed_message = _error(lambda: cf.get_resource_policy(ResourceArn=malformed_arn))
    assert malformed_code == "InvalidArgument", (
        f"expected InvalidArgument for malformed ARN, got {malformed_code!r}"
    )
    assert malformed_message == "ARNs must start with 'arn:'", (
        f"expected AWS's exact malformed-ARN message, got {malformed_message!r}"
    )

    real_arn = _create_vpc_origin_for_arn(ctx)

    # Positive control: the real, existing ARN succeeds (200) even though it
    # has never had a policy attached -- distinct from both the malformed
    # ARN's InvalidArgument and the missing ARN's EntityNotFound below.
    control_code, control_resp = _code_or_result(lambda: cf.get_resource_policy(ResourceArn=real_arn))
    assert control_code is None, (
        f"expected GetResourcePolicy to succeed for a real, existing VPC origin ARN, got {control_code!r}"
    )
    assert json.loads(control_resp["PolicyDocument"]) == {}, (
        f"expected an empty PolicyDocument for a real VPC origin with no policy attached, "
        f"got {control_resp['PolicyDocument']!r}"
    )

    # A hand-built VPC-origin ARN is rejected as InvalidArgument ("invalid resource type"), so
    # derive the missing ARN from a real one, swapping only the id segment.
    prefix, _, real_id = real_arn.rpartition("/")
    missing_arn = f"{prefix}/{real_id[:-4]}MISS" if len(real_id) > 4 else f"{prefix}/MISSING{real_id}"
    missing_code, missing_message = _error(lambda: cf.get_resource_policy(ResourceArn=missing_arn))
    assert missing_code == "EntityNotFound", (
        f"expected EntityNotFound for well-formed missing ARN, got {missing_code!r} (arn={missing_arn!r})"
    )
    assert missing_message == "The specified resource doesn't exist. Update your request and try again.", (
        f"expected AWS's exact not-found message for the missing ARN, got {missing_message!r}"
    )

    assert malformed_code != missing_code

    # The probe against a sibling ARN must not change the real ARN's policy-less state.
    restore_code, restore_resp = _code_or_result(lambda: cf.get_resource_policy(ResourceArn=real_arn))
    assert restore_code is None, (
        f"expected GetResourcePolicy to still succeed for the real ARN after the negative probe, got {restore_code!r}"
    )
    assert restore_resp["PolicyDocument"] == control_resp["PolicyDocument"], (
        "expected the real ARN's resource policy to be unchanged by the missing-ARN probe"
    )


def _create_vpc_origin_for_arn(ctx) -> str:
    """Launch a minimal EC2 instance and back a real CloudFront VPC origin with it,
    returning the VPC origin's real, service-validated ARN. Cleans up both."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    cf = ctx.client("cloudfront")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch the EC2 instance backing a VPC origin")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("the shared network has no subnets to launch the EC2 instance backing a VPC origin")
    subnet_id = subnets[0]["SubnetId"]

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-cf-vpco-")
    run_resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = run_resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    instance_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"

    try:
        created = cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name,
                "Arn": instance_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
            }
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "UnsupportedOperation":
            raise AssertionError(f"VPC origins are not supported in {ctx.region}: {exc}") from exc
        raise
    vpc_origin_id = created["VpcOrigin"]["Id"]
    vpc_origin_arn = created["VpcOrigin"]["Arn"]
    ctx.on_cleanup(lambda: _teardown_vpc_origin(ctx, vpc_origin_id))
    return vpc_origin_arn


def _teardown_vpc_origin(ctx, vpc_origin_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    resp = None
    while time.monotonic() < deadline:
        resp = cf.get_vpc_origin(Id=vpc_origin_id)
        if resp["VpcOrigin"]["Status"] == "Deployed":
            break
        time.sleep(interval_s)
    if resp is None or resp["VpcOrigin"]["Status"] != "Deployed":
        raise AssertionError(f"VPC origin {vpc_origin_id} never reached Deployed within {timeout_s}s for teardown")
    cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=resp["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
