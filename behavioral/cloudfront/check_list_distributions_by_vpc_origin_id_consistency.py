"""list-distributions-by-vpc-origin-id-consistency."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-vpc-origin-id-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution whose origin points at a VPC origin appears in
    ListDistributionsByVpcOriginId for that VPC origin's id.
    """
    subnet_ids, sg_id = _create_own_vpc_subnets_and_sg(ctx)
    alb_arn, alb_dns = _create_internal_alb(ctx, subnet_ids, sg_id)
    vpc_origin_id = _create_vpc_origin(ctx, alb_arn)
    dist_id = _create_distribution_with_vpc_origin(ctx, vpc_origin_id, alb_dns)

    ids = _poll_ids_by_vpc_origin(ctx, vpc_origin_id, dist_id, timeout_s=180.0)
    assert dist_id in ids, "distribution referencing the VPC origin never appeared in ListDistributionsByVpcOriginId"


# ===== helpers =====
def _create_own_vpc_subnets_and_sg(ctx):
    """Provision a minimal own VPC (2 subnets in different AZs, one security group) to host
    the ALB, rather than depending on an ambient default VPC that a freshly provisioned
    account may not have."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-cf-vo-")

    vpc = ec2.create_vpc(
        CidrBlock="10.180.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))

    # CreateVpcOrigin rejects a VPC with no internet gateway attached (InvalidArgument) even
    # though the ALB it targets is internal-only; a default VPC carries one implicitly.
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": name}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _detach_and_delete_igw(ec2, igw_id, vpc_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region!r} does not have 2 available AZs to host an ALB")
    az_names = [azs[0]["ZoneName"], azs[1]["ZoneName"]]

    subnet_ids = []
    for i, (cidr, az) in enumerate(zip(["10.180.1.0/24", "10.180.2.0/24"], az_names)):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name}-{i}"}]}],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))

    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real CloudFront VPC-origin consistency check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_when_vpc_free(ec2, sg_id, vpc_id))

    return subnet_ids, sg_id


def _retry_ec2(fn, gone: tuple, timeout_s: float = 180.0) -> None:
    """Run an EC2 teardown call: done on a `gone` code, retry DependencyViolation (ENIs still
    being released) every 2 s to the deadline, raise anything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _detach_and_delete_igw(ec2, igw_id: str, vpc_id: str) -> None:
    _retry_ec2(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id),
               ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"), timeout_s=60.0)
    _retry_ec2(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id),
               ("InvalidInternetGatewayID.NotFound",), timeout_s=30.0)


def _delete_vpc_with_retry(ec2, vpc_id: str, timeout_s: float = 90.0) -> None:
    _retry_ec2(lambda: ec2.delete_vpc(VpcId=vpc_id), ("InvalidVpcID.NotFound",), timeout_s)


def _delete_sg_when_vpc_free(ec2, sg_id: str, vpc_id: str, timeout_s: float = 480.0) -> None:
    """Teardown: wait every 2 s for the VPC's ENIs to go, then delete the security group.

    The subnet deletes that follow need the same ENIs gone. The teardown waits in this file add
    up to 1740 s of the suite's 1800 s cleanup budget.
    """
    deadline = time.monotonic() + timeout_s
    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]
    while time.monotonic() < deadline:
        if not ec2.describe_network_interfaces(Filters=vpc_filter)["NetworkInterfaces"]:
            break
        time.sleep(2)
    _retry_ec2(
        lambda: ec2.delete_security_group(GroupId=sg_id),
        ("InvalidGroup.NotFound",),
        max(0.0, deadline - time.monotonic()),
    )


def _create_internal_alb(ctx, subnet_ids, sg_id):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-cf-vo-")[:32].rstrip("-")
    resp = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": name}],
    )
    lb = resp["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_alb_and_wait(elbv2, lb_arn))

    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        got = elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])["LoadBalancers"][0]
        if got["State"]["Code"] == "active":
            return lb_arn, got["DNSName"]
        if got["State"]["Code"] == "failed":
            raise AssertionError(f"ALB failed to become active: {got['State']}")
        time.sleep(2)
    raise AssertionError("ALB never reached 'active' state within timeout")


def _delete_alb_and_wait(elbv2, lb_arn: str, timeout_s: float = 180.0) -> None:
    """DeleteLoadBalancer returns before its ENIs detach; wait for the describe to 404 so the
    subsequent security-group/subnet/VPC deletes do not hit DependencyViolation."""
    try:
        elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "LoadBalancerNotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[lb_arn])
        except Exception as exc:  # noqa: BLE001
            if "LoadBalancerNotFound" in str(exc):
                return
            raise
        time.sleep(10)


def _create_vpc_origin(ctx, alb_arn: str, timeout_s: float = 600.0) -> str:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-vo-")
    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": name,
            "Arn": alb_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "http-only",
        },
        Tags={"Items": [{"Key": "Name", "Value": name}]},
    )
    vpc_origin_id = resp["VpcOrigin"]["Id"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vpc_origin_id))

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = cf.get_vpc_origin(Id=vpc_origin_id)
        status = got["VpcOrigin"]["Status"]
        if status == "Deployed":
            return vpc_origin_id
        if status == "Failed":
            raise AssertionError("VPC origin deployment failed")
        time.sleep(2)
    raise AssertionError("VPC origin never reached 'Deployed' status within timeout")


def _delete_vpc_origin(ctx, vpc_origin_id: str, timeout_s: float = 180.0) -> None:
    """Delete the VPC origin, retrying while the deleted distribution still holds it or it is
    still deploying; raise anything else."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            got = cf.get_vpc_origin(Id=vpc_origin_id)
            cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=got["ETag"])
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFound":
                return
            if (code not in ("CannotDeleteEntityWhileInUse", "IllegalDelete", "PreconditionFailed")
                    or time.monotonic() >= deadline):
                raise
        time.sleep(2)


def _create_distribution_with_vpc_origin(ctx, vpc_origin_id: str, alb_dns: str) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-vod-")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": caller_ref,
                "Comment": "sim2real vpc-origin test distribution",
                "Enabled": True,
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "vpc-origin-1",
                            "DomainName": alb_dns,
                            "VpcOriginConfig": {
                                "VpcOriginId": vpc_origin_id,
                                "OriginReadTimeout": 30,
                                "OriginKeepaliveTimeout": 5,
                            },
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "vpc-origin-1",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
                },
            },
            "Tags": {"Items": [{"Key": "Name", "Value": caller_ref}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str, timeout_s: float = 720.0) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    dist_config = cfg_resp["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        try:
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=dist_config)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "EntityNotFound",
                "NoSuchCachePolicy",
                "NoSuchContinuousDeploymentPolicy",
                "NoSuchDistribution",
                "NoSuchFieldLevelEncryptionConfig",
                "NoSuchOrigin",
                "NoSuchOriginRequestPolicy",
                "NoSuchRealtimeLogConfig",
                "NoSuchResponseHeadersPolicy",
                "TrustedKeyGroupDoesNotExist",
                "TrustedSignerDoesNotExist",
            ):
                raise
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        if got["Distribution"]["Status"] == "Deployed":
            etag = got["ETag"]
            break
        time.sleep(2)
    if etag is None:
        raise AssertionError(f"distribution {dist_id} not Deployed within {timeout_s}s; not deleted")
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _poll_ids_by_vpc_origin(ctx, vpc_origin_id: str, dist_id: str, timeout_s: float = 120.0) -> set:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    ids: set = set()
    while time.monotonic() < deadline:
        resp = cf.list_distributions_by_vpc_origin_id(VpcOriginId=vpc_origin_id)
        ids = set(resp.get("DistributionIdList", {}).get("Items", []) or [])
        if dist_id in ids:
            return ids
        time.sleep(5)
    return ids


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
