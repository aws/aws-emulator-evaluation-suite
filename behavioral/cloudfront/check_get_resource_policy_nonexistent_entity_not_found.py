"""get-resource-policy-nonexistent-entity-not-found."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "get-resource-policy-nonexistent-entity-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy on a VPC origin with no policy returns the empty document "{}" rather than
    EntityNotFound; after PutResourcePolicy it returns that policy verbatim, and after
    DeleteResourcePolicy it returns "{}" again."""
    cf = ctx.client("cloudfront")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    vpc_origin_arn = _create_vpc_origin(ctx, cf, ec2, ssm)

    never_attached = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert never_attached["ResourceArn"] == vpc_origin_arn, (
        f"expected ResourceArn {vpc_origin_arn}, got {never_attached['ResourceArn']}"
    )
    assert json.loads(never_attached["PolicyDocument"]) == {}, (
        f"expected an empty policy document before any attach, got {never_attached['PolicyDocument']!r}"
    )

    policy_document = json.dumps(_sample_policy(vpc_origin_arn, ctx.account))
    cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=policy_document)
    ctx.on_cleanup(lambda: _delete_policy_if_present(cf, vpc_origin_arn))

    got = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert got["ResourceArn"] == vpc_origin_arn, f"expected ResourceArn {vpc_origin_arn}, got {got['ResourceArn']}"
    assert json.loads(got["PolicyDocument"]) == json.loads(policy_document), (
        f"expected policy document {policy_document}, got {got['PolicyDocument']}"
    )

    cf.delete_resource_policy(ResourceArn=vpc_origin_arn)
    after_delete = _poll_document(cf, vpc_origin_arn, want={}, timeout_s=600)
    assert after_delete == {}, f"expected the empty policy document after delete, got {after_delete!r}"


def _sample_policy(resource_arn: str, account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realCrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "cloudfront:GetVpcOrigin",
                "Resource": resource_arn,
            }
        ],
    }


def _poll_document(cf, resource_arn, want, timeout_s, interval_s=10):
    """Re-read the policy document until it equals ``want`` or ``timeout_s`` passes; return the
    last one read."""
    deadline = time.monotonic() + timeout_s
    while True:
        doc = json.loads(cf.get_resource_policy(ResourceArn=resource_arn)["PolicyDocument"])
        if doc == want or time.monotonic() >= deadline:
            return doc
        time.sleep(interval_s)


def _create_vpc_origin(ctx, cf, ec2, ssm) -> str:
    instance_id = _launch_backing_instance(ctx, ec2, ssm)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, instance_id))
    _wait_instance_running(ec2, instance_id)

    sts = ctx.client("sts")
    own_account = sts.get_caller_identity()["Account"]
    region = ec2.meta.region_name
    instance_arn = f"arn:aws:ec2:{region}:{own_account}:instance/{instance_id}"

    origin_name = ctx.unique_name("sim2real-cf-vpcorigin-")
    try:
        created = _create_vpc_origin_with_retry(
            cf,
            {
                "Name": origin_name,
                "Arn": instance_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
            },
        )
    except Exception as exc:  # noqa: BLE001
        from botocore.exceptions import ClientError

        if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "InternalError":
            raise AssertionError(
                f"CreateVpcOrigin persistently returns InternalError for an "
                f"EC2-instance-backed origin in this account/region: {exc}"
            ) from exc
        raise
    vpc_origin = created["VpcOrigin"]
    vpc_origin_id = vpc_origin["Id"]
    ctx.on_cleanup(lambda: _cleanup_vpc_origin(cf, vpc_origin_id))
    # PutResourcePolicy rejects an origin that has not finished deploying (IllegalUpdate).
    _wait_vpc_origin_deployed(cf, vpc_origin_id)
    return vpc_origin["Arn"]


def _launch_backing_instance(ctx, ec2, ssm):
    """Launches the origin's backing instance in the run's shared network, which has what
    CreateVpcOrigin needs of an instance's subnet (DNS hostnames and a route to an internet
    gateway, like a default VPC's default subnet), in an availability zone offering t3.micro."""
    ami_id = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]

    offerings = ec2.describe_instance_type_offerings(
        LocationType="availability-zone", Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}]
    )["InstanceTypeOfferings"]
    supported_azs = {o["Location"] for o in offerings}
    net = ctx.network()
    subnet_id = next(
        (net.subnets[az] for az in net.availability_zones if az in supported_azs), net.subnet_ids[0]
    )

    name = ctx.unique_name("sim2real-cf-vpcorigin-backing-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    return resp["Instances"][0]["InstanceId"]


def _terminate_instance(ec2, instance_id):
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _wait_instance_running(ec2, instance_id, timeout_s=120, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError:
            time.sleep(interval_s)
            continue
        state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} did not reach running within {timeout_s}s (last={state})")


def _create_vpc_origin_with_retry(cf, endpoint_config, attempts=3, base_delay_s=6):
    from botocore.exceptions import ClientError

    last_exc = None
    for attempt in range(attempts):
        try:
            return cf.create_vpc_origin(VpcOriginEndpointConfig=endpoint_config)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InternalError", "Throttling", "TooManyRequests"):
                raise
            last_exc = exc
            time.sleep(base_delay_s * (attempt + 1))
    raise last_exc


def _wait_vpc_origin_deployed(cf, vpc_origin_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_vpc_origin(Id=vpc_origin_id)["VpcOrigin"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vpc_origin_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_vpc_origin(cf, vpc_origin_id):
    from botocore.exceptions import ClientError

    try:
        cf.get_vpc_origin(Id=vpc_origin_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchVpcOrigin", "EntityNotFound"):
            return
        raise
    _wait_vpc_origin_deployed(cf, vpc_origin_id)
    etag = cf.get_vpc_origin(Id=vpc_origin_id)["ETag"]
    try:
        cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchVpcOrigin", "EntityNotFound"):
            return
        raise


def _delete_policy_if_present(cf, resource_arn) -> None:
    from botocore.exceptions import ClientError

    try:
        cf.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
