"""list-distributions-by-vpc-origin-id-filters-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-vpc-origin-id-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByVpcOriginId returns exactly the distributions that reference the
    given VPC origin, and excludes a sibling distribution that uses a plain custom origin
    instead."""
    cf = ctx.client("cloudfront")

    alb_arn, alb_dns = _create_minimal_internal_alb(ctx)

    vpc_origin_name = ctx.unique_name("sim2real-vpcorigin-")
    vo_resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": vpc_origin_name,
            "Arn": alb_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "http-only",
        },
        Tags={"Items": [{"Key": "Name", "Value": vpc_origin_name}]},
    )
    vpc_origin_id = vo_resp["VpcOrigin"]["Id"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(cf, vpc_origin_id))
    _wait_vpc_origin_deployed(cf, vpc_origin_id)

    bound_id = _create_distribution(ctx, "vpc-origin-filter bound", vpc_origin_id=vpc_origin_id, domain=alb_dns)
    unbound_id = _create_distribution(ctx, "vpc-origin-filter unbound", vpc_origin_id=None, domain="origin.example.com")

    filtered_ids = _collect_all_ids(cf.list_distributions_by_vpc_origin_id, VpcOriginId=vpc_origin_id)
    assert bound_id in filtered_ids, "the VPC-origin-bound distribution is missing from the filtered list"
    assert unbound_id not in filtered_ids, "an unrelated distribution leaked into the filtered list"


def _wait_vpc_origin_deployed(cf, vpc_origin_id: str, timeout_s: float = 900.0) -> None:
    """Wait for the VPC origin to reach Deployed: CreateDistribution rejects one still in progress
    with InvalidArgument ("crud operation is in progress") rather than waiting."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cf.get_vpc_origin(Id=vpc_origin_id)["VpcOrigin"]["Status"]
        if status == "Deployed":
            return
        if status == "Failed":
            raise AssertionError(f"VPC origin {vpc_origin_id} failed to deploy")
        time.sleep(2)
    raise AssertionError(f"VPC origin {vpc_origin_id} never reached 'Deployed' within {timeout_s}s")


def _delete_vpc_origin(cf, vpc_origin_id: str, timeout_s: float = 900.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = cf.get_vpc_origin(Id=vpc_origin_id)
        status = got["VpcOrigin"]["Status"]
        if status in ("Deployed", "Failed"):
            cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=got["ETag"])
            return
        time.sleep(15)
    raise AssertionError(f"VPC origin {vpc_origin_id} never left an in-progress state within {timeout_s}s")


def _collect_all_ids(list_fn, **kwargs) -> set[str]:
    ids: set[str] = set()
    marker = None
    while True:
        params = dict(kwargs)
        params["MaxItems"] = "100"
        if marker:
            params["Marker"] = marker
        resp = list_fn(**params)
        body = resp["DistributionIdList"] if "DistributionIdList" in resp else resp["DistributionList"]
        items = body.get("Items", [])
        for item in items:
            ids.add(item if isinstance(item, str) else item["Id"])
        if not body.get("IsTruncated"):
            break
        marker = body.get("NextMarker")
        if not marker:
            break
    return ids


def _create_distribution(ctx, comment: str, vpc_origin_id, domain: str) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-vpcorigin-dist-")
    origin = {"Id": "origin1", "DomainName": domain}
    if vpc_origin_id:
        origin["VpcOriginConfig"] = {"VpcOriginId": vpc_origin_id}
    else:
        origin["CustomOriginConfig"] = {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
        }
    config = {
        "CallerReference": caller_ref,
        "Comment": comment,
        "Enabled": False,
        "Origins": {"Quantity": 1, "Items": [origin]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "Name", "Value": caller_ref}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_minimal_internal_alb(ctx) -> tuple[str, str]:
    """Provision a minimal internal ALB (own VPC, IGW, two subnets, one security group) whose ARN
    CreateVpcOrigin can reference. CreateVpcOrigin rejects a VPC without an internet gateway, so
    one is attached although no traffic flows; cleanup is registered so LIFO deletes in reverse."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    tag_name = ctx.unique_name("sim2real-vpcorigin-alb-")

    vpc = ec2.create_vpc(
        CidrBlock="10.171.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_with_retry(ec2, vpc_id))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": tag_name}]}]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _detach_and_delete_igw(ec2, igw_id, vpc_id))

    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region!r} does not have 2 available AZs to host an ALB")
    az_names = [azs[0]["ZoneName"], azs[1]["ZoneName"]]

    subnet_ids = []
    for i, (cidr, az) in enumerate(zip(["10.171.1.0/24", "10.171.2.0/24"], az_names)):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{tag_name}-{i}"}]}],
        )["Subnet"]
        subnet_id = subnet["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    sg = ec2.create_security_group(
        GroupName=tag_name,
        Description="sim2real CloudFront VPC-origin filter check",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id))

    lb = elbv2.create_load_balancer(
        Name=tag_name[:32].strip("-"),
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": tag_name}],
    )["LoadBalancers"][0]
    alb_arn = lb["LoadBalancerArn"]
    alb_dns = lb["DNSName"]
    ctx.on_cleanup(lambda: _delete_alb_and_wait(elbv2, alb_arn))

    return alb_arn, alb_dns


def _delete_alb_and_wait(elbv2, alb_arn: str) -> None:
    elbv2.delete_load_balancer(LoadBalancerArn=alb_arn)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            elbv2.describe_load_balancers(LoadBalancerArns=[alb_arn])
        except Exception as exc:  # noqa: BLE001
            if "LoadBalancerNotFound" in str(exc):
                return
            raise
        time.sleep(10)


def _detach_and_delete_igw(ec2, igw_id: str, vpc_id: str) -> None:
    try:
        _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
    except Exception as exc:  # noqa: BLE001
        if "Gateway.NotAttached" not in str(exc):
            raise
    _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)


def _delete_vpc_with_retry(ec2, vpc_id: str) -> None:
    """DeleteVpc; _delete_net retries DependencyViolation, a gone VPC is done."""
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


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
