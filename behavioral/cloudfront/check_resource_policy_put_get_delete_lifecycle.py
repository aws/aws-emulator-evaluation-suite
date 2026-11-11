"""resource-policy-put-get-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-put-get-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy attaches a policy to a VPC origin that GetResourcePolicy returns verbatim;
    after DeleteResourcePolicy, GetResourcePolicy succeeds with an empty `{}` document, not
    EntityNotFound (the resource still exists, with no policy attached).
    """
    cf = ctx.client("cloudfront")
    vpc_origin_arn = _create_vpc_origin(ctx)

    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy_document = _policy_document(account_id, vpc_origin_arn, action="cloudfront:GetVpcOrigin")

    cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=policy_document)

    fetched = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert fetched["ResourceArn"] == vpc_origin_arn
    assert _normalize(fetched["PolicyDocument"]) == _normalize(policy_document)

    cf.delete_resource_policy(ResourceArn=vpc_origin_arn)

    cleared = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert cleared["ResourceArn"] == vpc_origin_arn
    assert _normalize(cleared["PolicyDocument"]) == {}, (
        f"expected an empty PolicyDocument after delete, got {cleared['PolicyDocument']!r}"
    )




def _normalize(policy_json: str):
    import json

    return json.loads(policy_json)


def _policy_document(account_id: str, resource_arn: str, action: str) -> str:
    import json

    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Sim2RealResourcePolicyLifecycle",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": action,
                    "Resource": resource_arn,
                }
            ],
        }
    )


def _create_vpc_origin(ctx) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch the EC2 instance backing a VPC origin")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("the shared network has no subnets to launch the EC2 instance backing a VPC origin")

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-cf-vpco-")
    instance_id = None
    for subnet in subnets:
        try:
            run_resp = ec2.run_instances(
                ImageId=ami_id,
                InstanceType="t3.micro",
                MinCount=1,
                MaxCount=1,
                SubnetId=subnet["SubnetId"],
                TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
            )
        except ClientError as exc:
            # t3.micro isn't offered in every AZ of the default VPC (us-east-1e rejects it),
            # so try the remaining subnets before giving up.
            if exc.response["Error"]["Code"] == "Unsupported":
                continue
            raise
        instance_id = run_resp["Instances"][0]["InstanceId"]
        break
    if instance_id is None:
        raise AssertionError(
            f"t3.micro is not supported in any subnet's AZ of the run's shared network {vpc_id}"
        )
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

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
    # PutResourcePolicy is rejected with IllegalUpdate while the resource hasn't finished
    # deploying, so wait for the VPC origin to reach Deployed before returning it.
    _wait_vpc_origin_deployed(ctx, vpc_origin_id)
    return vpc_origin_arn


def _wait_vpc_origin_deployed(ctx, vpc_origin_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_vpc_origin(Id=vpc_origin_id)
        if resp["VpcOrigin"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"VPC origin {vpc_origin_id} never reached Deployed within {timeout_s}s")


def _teardown_vpc_origin(ctx, vpc_origin_id: str) -> None:
    cf = ctx.client("cloudfront")
    resp = _wait_vpc_origin_deployed(ctx, vpc_origin_id)
    try:
        cf.delete_resource_policy(ResourceArn=resp["VpcOrigin"]["Arn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
    # Deleting the policy changes the VPC origin's ETag, so read the current one for the delete.
    resp = _wait_vpc_origin_deployed(ctx, vpc_origin_id)
    cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=resp["ETag"])
    deadline = time.monotonic() + 1500.0
    while time.monotonic() < deadline:
        try:
            cf.get_vpc_origin(Id=vpc_origin_id)
        except cf.exceptions.EntityNotFound:
            return
        time.sleep(15.0)
    raise AssertionError(f"VPC origin {vpc_origin_id} still exists 1500s after DeleteVpcOrigin")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
