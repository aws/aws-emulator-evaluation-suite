"""list-distributions-by-vpc-origin-id-index-consistency."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-distributions-by-vpc-origin-id-index-consistency"
GROUP = "data-plane"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1800.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return resp["ETag"]


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    try:
        cf.get_distribution(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return  # already deleted by the check body itself
        raise
    etag = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_own_subnet(ctx):
    """Create a minimal VPC + subnet to host the EC2 instance backing the CloudFront VPC
    origin, so the check does not depend on an ambient default VPC existing in the account.
    CreateVpcOrigin rejects an EC2-instance-backed origin whose VPC has no internet gateway
    ("does not have an internet gateway in its VPC"), so one is attached with a default route
    even though the check never sends real traffic through it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-cf-vpco-net-")
    vpc = ec2.create_vpc(
        CidrBlock="10.172.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _detach_and_delete_igw(ec2, igw_id, vpc_id))

    route_table_id = ec2.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "association.main", "Values": ["true"]}]
    )["RouteTables"][0]["RouteTableId"]
    ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not azs:
        raise AssertionError(
            f"region {ctx.region!r} has no available availability zone to host the "
            "VPC-origin backing instance"
        )

    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.172.1.0/24",
        AvailabilityZone=azs[0]["ZoneName"],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_id


def _detach_and_delete_igw(ec2, igw_id, vpc_id):
    _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)


def _delete_vpc_with_retry(ec2, vpc_id, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"VPC {vpc_id} could not be deleted within {timeout_s}s: {last_exc}")


def _terminate_instance_and_wait(ec2, instance_id, timeout_s=300.0, interval_s=10.0):
    ec2.terminate_instances(InstanceIds=[instance_id])
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "terminated":
            return
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} did not reach 'terminated' within {timeout_s}s")


def _launch_backing_instance(ctx):
    """Launch a minimal EC2 instance whose ARN backs a CloudFront VPC origin; no traffic flows."""
    ec2 = ctx.client("ec2")
    subnet_id = _create_own_subnet(ctx)

    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2 AMI found to launch the VPC-origin backing instance")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    ami_id = images[0]["ImageId"]

    name = ctx.unique_name("sim2real-cf-vpco-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    instance = resp["Instances"][0]
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_instance_and_wait(ec2, instance_id))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    instance_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"
    private_dns = instance.get("PrivateDnsName") or _poll_until(
        lambda: ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0],
        lambda i: bool(i.get("PrivateDnsName")),
        timeout_s=120.0,
        interval_s=5.0,
    )["PrivateDnsName"]
    return instance_arn, private_dns


def _create_vpc_origin(ctx):
    cf = ctx.client("cloudfront")
    instance_arn, private_dns = _launch_backing_instance(ctx)
    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": ctx.unique_name("sim2real-vpco-"),
            "Arn": instance_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "http-only",
        }
    )
    vpc_origin = resp["VpcOrigin"]
    vpc_origin_id = vpc_origin["Id"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vpc_origin_id))

    # CreateDistribution rejects a VPC origin still mid-CRUD ("A crud operation is in
    # progress or failed for the specified vpcorigin resource"), so it must reach a
    # terminal status before it can be referenced by a new distribution's origin config.
    deployed = _poll_until(
        lambda: cf.get_vpc_origin(Id=vpc_origin_id),
        lambda r: r["VpcOrigin"]["Status"] in ("Deployed", "Failed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    if deployed["VpcOrigin"]["Status"] == "Failed":
        raise AssertionError(f"VPC origin {vpc_origin_id} failed to deploy")
    return vpc_origin_id, private_dns


def _delete_vpc_origin(ctx, vpc_origin_id):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_vpc_origin(Id=vpc_origin_id),
        lambda r: r["VpcOrigin"]["Status"] in ("Deployed", "Failed"),
        timeout_s=1200.0,
        interval_s=15.0,
    )
    cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=resp["ETag"])


def _create_distribution_with_vpc_origin(ctx, vpc_origin_id, domain_name):
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-"),
            "Comment": "sim2real behavioral check distribution",
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "vpc-origin",
                        "DomainName": domain_name,
                        "VpcOriginConfig": {"VpcOriginId": vpc_origin_id},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "vpc-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _list_by_vpc_origin_id(cf, vpc_origin_id):
    ids = set()
    marker = None
    while True:
        kwargs = {"VpcOriginId": vpc_origin_id, "MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distributions_by_vpc_origin_id(**kwargs)
        idlist = resp["DistributionIdList"]
        ids.update(idlist.get("Items", []))
        marker = idlist.get("NextMarker")
        if not marker:
            break
    return ids


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution referencing a VPC origin appears in ListDistributionsByVpcOriginId,
    and disappears once the distribution that references it is deleted."""
    cf = ctx.client("cloudfront")
    vpc_origin_id, private_dns = _create_vpc_origin(ctx)
    dist_id = _create_distribution_with_vpc_origin(ctx, vpc_origin_id, private_dns)

    ids_after_create = _poll_until(
        lambda: _list_by_vpc_origin_id(cf, vpc_origin_id),
        lambda ids: dist_id in ids,
        timeout_s=1800.0,
        interval_s=15.0,
    )
    assert dist_id in ids_after_create, (
        f"distribution {dist_id} referencing VPC origin {vpc_origin_id} never appeared in "
        f"ListDistributionsByVpcOriginId (saw {sorted(ids_after_create)})"
    )

    # Deleting the referencing distribution removes it from the index.
    _delete_distribution(ctx, dist_id)

    ids_after_delete = _poll_until(
        lambda: _list_by_vpc_origin_id(cf, vpc_origin_id),
        lambda ids: dist_id not in ids,
        timeout_s=600.0,
        interval_s=15.0,
    )
    assert dist_id not in ids_after_delete, (
        f"deleted distribution {dist_id} still appears in ListDistributionsByVpcOriginId for "
        f"VPC origin {vpc_origin_id} (saw {sorted(ids_after_delete)})"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the
# resource's ENIs to go, retry DependencyViolation inside the same window, and raise a final failure
# naming the ENIs still attached. Every other error propagates. Only teardown calls this.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
