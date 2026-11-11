"""op-contract-getResourcePolicy."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getResourcePolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourcePolicy rejects a malformed ARN and an unsupported resource type with InvalidArgument,
    while a VPC origin with no policy (never attached, or deleted) reads back as 200 with "{}"."""
    cf = ctx.client("cloudfront")

    malformed_code, malformed_msg = _error(lambda: cf.get_resource_policy(ResourceArn="this-is-not-an-arn"))
    if malformed_code == "UnsupportedOperation":
        raise AssertionError("GetResourcePolicy unsupported in this account/region")
    assert malformed_code == "InvalidArgument", (
        f"expected InvalidArgument for a malformed ResourceArn, got {malformed_code}"
    )
    assert malformed_msg == "ARNs must start with 'arn:'", f"unexpected message for a malformed ResourceArn: {malformed_msg!r}"

    account_id = _account_id(ctx)

    name = ctx.unique_name("sim2real-rp-kvs-")
    kvs = cf.create_key_value_store(
        Name=name,
        Comment="sim2real behavioral check",
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    kvs_arn = kvs["KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _safe_delete_kvs(cf, name))
    _wait_kvs_ready(cf, name)

    # A real resource of an unsupported type gets the same InvalidArgument code as a malformed
    # ARN; only the message differs between Get and Put.
    wrong_type_get_code, wrong_type_get_msg = _error(lambda: cf.get_resource_policy(ResourceArn=kvs_arn))
    assert wrong_type_get_code == "InvalidArgument", (
        f"expected InvalidArgument for a well-formed ARN of an unsupported resource type, got {wrong_type_get_code}"
    )
    assert wrong_type_get_msg == "The ResourceArn parameter is required. Specify a valid ARN and try again.", f"unexpected GetResourcePolicy wrong-type message: {wrong_type_get_msg!r}"

    kvs_policy_doc = _policy_document(account_id, kvs_arn, "cloudfront:DescribeKeyValueStore")
    wrong_type_put_code, wrong_type_put_msg = _error(
        lambda: cf.put_resource_policy(ResourceArn=kvs_arn, PolicyDocument=kvs_policy_doc)
    )
    assert wrong_type_put_code == "InvalidArgument", (
        f"expected InvalidArgument for PutResourcePolicy against an unsupported resource type, got {wrong_type_put_code}"
    )
    assert wrong_type_put_msg == "The specified resource type isn't valid. Specify a VPC origin and try again.", f"unexpected PutResourcePolicy wrong-type message: {wrong_type_put_msg!r}"

    vpc_origin_arn = _create_vpc_origin(ctx)

    # A supported resource with no policy attached is not EntityNotFound but a 200 with "{}".
    never_had_policy_resp = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert never_had_policy_resp["ResourceArn"] == vpc_origin_arn, (
        f"expected ResourceArn {vpc_origin_arn}, got {never_had_policy_resp['ResourceArn']}"
    )
    assert json.loads(never_had_policy_resp["PolicyDocument"]) == {}, (
        "expected an empty policy document for a VPC origin that never had one attached, got "
        f"{never_had_policy_resp['PolicyDocument']!r}"
    )

    policy_doc = _policy_document(account_id, vpc_origin_arn, "cloudfront:GetVpcOrigin")
    cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=policy_doc)

    fetched = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert fetched["ResourceArn"] == vpc_origin_arn, (
        f"expected ResourceArn {vpc_origin_arn}, got {fetched['ResourceArn']}"
    )
    assert json.loads(fetched["PolicyDocument"]) == json.loads(policy_doc), (
        "GetResourcePolicy must return the attached policy document verbatim"
    )
    assert json.loads(fetched["PolicyDocument"]) != {}, (
        "an attached policy must read back as itself, not fall back to the empty default"
    )

    cf.delete_resource_policy(ResourceArn=vpc_origin_arn)

    # After delete, GetResourcePolicy reverts to the same 200/"{}" shape, not EntityNotFound.
    after_delete_resp = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert json.loads(after_delete_resp["PolicyDocument"]) == {}, (
        "expected the policy document to revert to empty after delete, got "
        f"{after_delete_resp['PolicyDocument']!r}"
    )


def _error(fn):
    """Call fn() and return the ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    sts = ctx.client("sts")
    return sts.get_caller_identity()["Account"]


def _policy_document(account_id: str, resource_arn: str, action: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": action,
                    "Resource": resource_arn,
                }
            ],
        }
    )


def _wait_kvs_ready(cf, name: str, timeout_s: float = 120.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cf.describe_key_value_store(Name=name)["KeyValueStore"]["Status"]
        if status.upper() == "READY":
            return
        time.sleep(interval_s)
    raise AssertionError(f"key value store {name} never reached READY within {timeout_s}s")


def _safe_delete_kvs(cf, name: str) -> None:
    try:
        current = cf.describe_key_value_store(Name=name)
        cf.delete_key_value_store(Name=name, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _launch_backing_instance(ctx, ec2, ssm) -> str:
    """Launch an instance in a new VPC with an attached but unrouted internet gateway.

    CreateVpcOrigin requires an IGW in the VPC, yet fails with InternalError for a public subnet."""
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    vpc_cidr = "10.233.0.0/24"
    vpc_id = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_vpc_network(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=vpc_cidr)["Subnet"]["SubnetId"]
    ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    name = ctx.unique_name("sim2real-rp-vpco-backing-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    return resp["Instances"][0]["InstanceId"]


def _delete_vpc_network(ec2, vpc_id: str, timeout_s: float = 400.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
            for subnet in subnets:
                ec2.delete_subnet(SubnetId=subnet["SubnetId"])
            igws = ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            )["InternetGateways"]
            for igw in igws:
                ec2.detach_internet_gateway(InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
                ec2.delete_internet_gateway(InternetGatewayId=igw["InternetGatewayId"])
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code == "DependencyViolation":
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"could not tear down vpc {vpc_id} within {timeout_s}s (DependencyViolation persisted)")


def _create_vpc_origin(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    cf = ctx.client("cloudfront")

    instance_id = _launch_backing_instance(ctx, ec2, ssm)
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    account_id = _account_id(ctx)
    instance_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
    name = ctx.unique_name("sim2real-rp-vpco-")

    try:
        created = cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": name,
                "Arn": instance_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
            },
            Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
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


def _teardown_vpc_origin(ctx, vpc_origin_id: str, gone_timeout_s: float = 450.0, interval_s: float = 15.0) -> None:
    """Delete the VPC origin and wait until it is gone, so the VPC teardown registered before
    it does not race the origin's network interfaces. DeleteResourcePolicy changes the
    origin's ETag, so the delete uses a freshly read one."""
    cf = ctx.client("cloudfront")
    resp = _wait_vpc_origin_deployed(ctx, vpc_origin_id)
    try:
        cf.delete_resource_policy(ResourceArn=resp["VpcOrigin"]["Arn"])
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFound":
            raise
    resp = _wait_vpc_origin_deployed(ctx, vpc_origin_id)
    cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=resp["ETag"])
    deadline = time.monotonic() + gone_timeout_s
    while True:
        try:
            cf.get_vpc_origin(Id=vpc_origin_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityNotFound":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPC origin {vpc_origin_id} still present {gone_timeout_s}s after delete")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
