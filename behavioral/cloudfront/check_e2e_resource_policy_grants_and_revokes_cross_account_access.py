"""e2e-resource-policy-grants-and-revokes-cross-account-access."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-resource-policy-grants-and-revokes-cross-account-access"
GROUP = "e2e"
SERVICES = ["cloudfront"]


#: The AWS documentation placeholder account; PutResourcePolicy refuses a principal that does not exist.
_PLACEHOLDER_ACCOUNT = "111122223333"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy on a deployed VPC origin refuses a grant to an account that does not exist
    and stores nothing; a grant to the owner's account round-trips through GetResourcePolicy, and
    DeleteResourcePolicy revokes it back to the empty placeholder document.
    """
    cf = ctx.client("cloudfront")
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")

    owner_account = ctx.client("sts").get_caller_identity()["Account"]

    net = _create_network(ctx, ec2)
    lb_arn = _create_backing_alb(ctx, elbv2, net["subnets"])

    created = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": ctx.unique_name("sim2real-cf-vpcorigin-"),
            "Arn": lb_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "http-only",
        }
    )
    vpc_origin_id = created["VpcOrigin"]["Id"]
    vpc_origin_arn = created["VpcOrigin"]["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin_and_wait(cf, vpc_origin_id))

    _wait_vpc_origin_deployed(cf, vpc_origin_id)

    before = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert before["ResourceArn"] == vpc_origin_arn, before["ResourceArn"]
    assert json.loads(before["PolicyDocument"]) == {}, (
        f"expected the empty placeholder policy before any grant, got {before['PolicyDocument']!r}"
    )

    code, message = _error(
        lambda: cf.put_resource_policy(
            ResourceArn=vpc_origin_arn,
            PolicyDocument=json.dumps(_grant(_PLACEHOLDER_ACCOUNT, vpc_origin_arn)),
        )
    )
    assert code == "InvalidArgument", (
        f"a grant to the nonexistent account {_PLACEHOLDER_ACCOUNT} must be refused with "
        f"InvalidArgument, got {code!r} (message={message!r})"
    )
    expected = (
        "The specified policy references a principal that doesn't exist. "
        "Verify the principals in the policy and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    refused = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert json.loads(refused["PolicyDocument"]) == {}, (
        f"a refused PutResourcePolicy must store nothing, got {refused['PolicyDocument']!r}"
    )

    policy_document = _grant(owner_account, vpc_origin_arn)
    put = cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=json.dumps(policy_document))
    assert put["ResourceArn"] == vpc_origin_arn, put["ResourceArn"]

    got = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    statements = json.loads(got["PolicyDocument"])["Statement"]
    assert len(statements) == 1, statements
    stored = statements[0]
    assert stored["Sid"] == "sim2realCrossAccountRead", stored
    assert stored["Effect"] == "Allow", stored
    assert stored["Principal"]["AWS"] == f"arn:aws:iam::{owner_account}:root", stored
    actions = stored["Action"] if isinstance(stored["Action"], list) else [stored["Action"]]
    assert actions == ["cloudfront:GetVpcOrigin"], stored
    assert stored["Resource"] == vpc_origin_arn, stored

    cf.delete_resource_policy(ResourceArn=vpc_origin_arn)

    after = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert json.loads(after["PolicyDocument"]) == {}, (
        f"expected DeleteResourcePolicy to revoke the grant back to the empty placeholder, "
        f"got {after['PolicyDocument']!r}"
    )

    # Tear down inside the check budget: the VPC origin delete and the ALB's ENIs outlast the
    # cleanup budget together. The registered cleanups stay as the backstop.
    _delete_vpc_origin_and_wait(cf, vpc_origin_id)
    _delete_alb(elbv2, lb_arn)
    _delete_network(ec2, net)



def _grant(account: str, resource_arn: str) -> dict:
    """A one-statement policy letting ``account`` read the VPC origin."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realCrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": ["cloudfront:GetVpcOrigin"],
                "Resource": resource_arn,
            }
        ],
    }


def _error(fn) -> tuple[str, str]:
    """Call fn() and return its error (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


_CIDR = "10.84.0.0/16"


def _create_network(ctx, ec2) -> dict:
    """A VPC with an attached internet gateway and one subnet in each of two AZs."""
    name = ctx.unique_name("sim2real-cf-vpcorigin-net-")
    tags = [{"Key": "Name", "Value": name}]
    net: dict = {"subnets": []}
    net["vpc"] = ec2.create_vpc(
        CidrBlock=_CIDR, TagSpecifications=[{"ResourceType": "vpc", "Tags": tags}]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_network(ec2, net))
    net["igw"] = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": tags}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw"], VpcId=net["vpc"])
    zones = ec2.describe_availability_zones(
        Filters=[
            {"Name": "state", "Values": ["available"]},
            {"Name": "zone-type", "Values": ["availability-zone"]},
        ]
    )["AvailabilityZones"]
    azs = [z["ZoneName"] for z in zones][:2]
    assert len(azs) == 2, f"expected two available AZs in {ctx.region}, got {azs}"
    for i, az in enumerate(azs):
        net["subnets"].append(
            ec2.create_subnet(
                VpcId=net["vpc"],
                CidrBlock=f"10.84.{i + 1}.0/24",
                AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": tags}],
            )["Subnet"]["SubnetId"]
        )
    return net


def _create_backing_alb(ctx, elbv2, subnet_ids) -> str:
    name = ctx.unique_name("sim2real-cf-vpcorigin-alb-")[:32]
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        Scheme="internal",
        Type="application",
        Tags=[{"Key": "Name", "Value": name}],
    )
    lb_arn = resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_alb(elbv2, lb_arn))
    return lb_arn


def _delete_alb(elbv2, lb_arn):
    from botocore.exceptions import ClientError

    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise


def _wait_vpc_origin_deployed(cf, vpc_origin_id, timeout_s=1200, interval_s=15):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_vpc_origin(Id=vpc_origin_id)["VpcOrigin"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vpc_origin_id} did not reach Deployed within {timeout_s}s (last={status})")


def _delete_vpc_origin_and_wait(cf, vpc_origin_id, timeout_s=1200, interval_s=15):
    """Delete once the origin is Deployed, then wait until it is gone; a gone origin is a no-op."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    deleted = False
    while time.monotonic() < deadline:
        try:
            got = cf.get_vpc_origin(Id=vpc_origin_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("NoSuchVpcOrigin", "EntityNotFound"):
                return
            raise
        if not deleted and got["VpcOrigin"]["Status"] == "Deployed":
            try:
                cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=got["ETag"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] in ("NoSuchVpcOrigin", "EntityNotFound"):
                    return
                raise
            deleted = True
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vpc_origin_id} was not gone within {timeout_s}s")


def _delete_network(ec2, net, timeout_s=600, interval_s=15):
    """Wait for the VPC's ENIs to drain, then delete subnets, the gateway and the VPC; idempotent."""
    vpc_id = net.get("vpc")
    if not vpc_id:
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        enis = ec2.describe_network_interfaces(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        if not enis["NetworkInterfaces"]:
            break
        time.sleep(interval_s)
    while net["subnets"]:
        _ec2_delete(lambda sid=net["subnets"][0]: ec2.delete_subnet(SubnetId=sid), deadline, interval_s)
        net["subnets"].pop(0)
    igw = net.pop("igw", None)
    if igw:
        _ec2_delete(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id), deadline, interval_s)
        _ec2_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw), deadline, interval_s)
    _ec2_delete(lambda: ec2.delete_vpc(VpcId=vpc_id), deadline, interval_s)
    net.pop("vpc", None)


def _ec2_delete(call, deadline, interval_s):
    """Retry DependencyViolation until the deadline; an already-gone resource is a no-op."""
    from botocore.exceptions import ClientError

    while True:
        try:
            call()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code.endswith("NotFound") or code == "Gateway.NotAttached":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
