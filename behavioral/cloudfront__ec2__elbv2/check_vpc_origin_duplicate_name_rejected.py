"""vpc-origin-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-origin-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront", "ec2", "elbv2"]

#: CloudFront's control plane is global and signed in us-east-1; the VPC and ALB live in ctx.region.
CLOUDFRONT_REGION = "us-east-1"

_ALB_ACTIVE_BUDGET_S = 600.0
_NETWORK_DELETE_BUDGET_S = 900.0
_VPC_ORIGIN_DELETE_BUDGET_S = 1200.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=10.0, description="condition"):
    """Bounded retry that RAISES on timeout, never returning a stale last value as success."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _retry_dependency_violation(fn, *not_found_codes, deadline, interval_s=5.0):
    """Call ``fn()``; swallow the resource's own not-found codes, retry DependencyViolation."""
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in not_found_codes:
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _delete_network(ec2, net, *, budget_s=_NETWORK_DELETE_BUDGET_S):
    """Delete the SG, subnets, the IGW and the VPC this check created, in that dependency order;
    ``net`` is filled in as each is created, so a setup that fails part-way is still torn down."""
    vpc_id = net["vpc"]
    deadline = time.monotonic() + budget_s
    _poll_until(
        lambda: len(ec2.describe_network_interfaces(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkInterfaces"]),
        lambda n: n == 0,
        timeout_s=max(1.0, deadline - time.monotonic()),
        interval_s=15.0,
        description=f"every ENI in {vpc_id} to go",
    )
    if net["sg"]:
        _retry_dependency_violation(
            lambda: ec2.delete_security_group(GroupId=net["sg"]),
            "InvalidGroup.NotFound", deadline=deadline,
        )
    for subnet_id in net["subnets"]:
        _retry_dependency_violation(
            lambda s=subnet_id: ec2.delete_subnet(SubnetId=s),
            "InvalidSubnetID.NotFound", deadline=deadline,
        )
    if net["igw"]:
        _retry_dependency_violation(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=net["igw"], VpcId=vpc_id),
            "Gateway.NotAttached", "InvalidInternetGatewayID.NotFound", deadline=deadline,
        )
        _retry_dependency_violation(
            lambda: ec2.delete_internet_gateway(InternetGatewayId=net["igw"]),
            "InvalidInternetGatewayID.NotFound", deadline=deadline,
        )
    _retry_dependency_violation(
        lambda: ec2.delete_vpc(VpcId=vpc_id),
        "InvalidVpcID.NotFound", deadline=deadline,
    )


def _delete_load_balancer(elb, lb_arn) -> None:
    """Delete the ALB and wait until it is gone, so its ENIs clear before the network teardown."""
    try:
        elb.delete_load_balancer(LoadBalancerArn=lb_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "LoadBalancerNotFound":
            return
        raise
    elb.get_waiter("load_balancers_deleted").wait(
        LoadBalancerArns=[lb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 450})


def _delete_vpc_origins(cf, vo_ids, *, timeout_s=_VPC_ORIGIN_DELETE_BUDGET_S) -> None:
    """Delete every VPC origin in ``vo_ids`` under one shared deadline, so the deploy and delete
    waits overlap instead of adding up: each is deleted once it is Deployed (delete is illegal
    before that), then all are awaited gone. A concurrent not-found is tolerated at every step."""
    deadline = time.monotonic() + timeout_s
    pending, deleting = list(vo_ids), []
    while pending or deleting:
        for vo_id in list(pending):
            try:
                origin = cf.get_vpc_origin(Id=vo_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFound":
                    raise
                pending.remove(vo_id)
                continue
            if origin["VpcOrigin"]["Status"] != "Deployed":
                continue
            try:
                cf.delete_vpc_origin(Id=vo_id, IfMatch=origin["ETag"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFound":
                    raise
            pending.remove(vo_id)
            deleting.append(vo_id)
        for vo_id in list(deleting):
            try:
                cf.get_vpc_origin(Id=vo_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFound":
                    raise
                deleting.remove(vo_id)
        if not (pending or deleting):
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"VPC origins not yet deleted {pending!r} and still deleting {deleting!r} after "
                f"{timeout_s}s"
            )
        time.sleep(15)


def _vpc_origin_names(cf) -> list[str]:
    """Every Name across all pages of ListVpcOrigins."""
    names, marker = [], None
    while True:
        page = cf.list_vpc_origins(**({"Marker": marker} if marker else {}))["VpcOriginList"]
        names += [i["Name"] for i in page.get("Items", [])]
        marker = page.get("NextMarker")
        if not marker:
            return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpcOrigin rejects a second VPC origin reusing an existing one's Name with
    EntityAlreadyExists and its exact message, creating nothing, while the identical config under
    a different Name succeeds and GetVpcOrigin reads it back unchanged.
    """
    ec2 = ctx.client("ec2")
    elb = ctx.client("elbv2")
    cf = ctx.client("cloudfront", region=CLOUDFRONT_REGION)

    name = ctx.unique_name("sim2real-vod-")

    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"])
    assert len(zones) >= 2, f"need 2 available AZs in {ctx.region}, found {zones!r}"

    vpc_id = ec2.create_vpc(
        CidrBlock="10.62.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    net = {"vpc": vpc_id, "igw": None, "subnets": [], "sg": None}
    ctx.on_cleanup(lambda: _delete_network(ec2, net))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway",
                            "Tags": [{"Key": "Name", "Value": name}]}],
    )["InternetGateway"]["InternetGatewayId"]
    net["igw"] = igw_id
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    for i, az in enumerate(zones[:2]):
        net["subnets"].append(ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.62.{i + 1}.0/24", AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet",
                                "Tags": [{"Key": "Name", "Value": name}]}],
        )["Subnet"]["SubnetId"])
    subnet_ids = net["subnets"]

    origin_facing = ec2.describe_managed_prefix_lists(Filters=[{
        "Name": "prefix-list-name", "Values": ["com.amazonaws.global.cloudfront.origin-facing"],
    }])["PrefixLists"][0]["PrefixListId"]
    sg_id = ec2.create_security_group(
        GroupName=name, Description=CHECK, VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group",
                            "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]
    net["sg"] = sg_id
    ec2.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=[{
        "IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
        "PrefixListIds": [{"PrefixListId": origin_facing}],
    }])

    lb_arn = elb.create_load_balancer(
        Name=name[:32].rstrip("-"), Subnets=subnet_ids, SecurityGroups=[sg_id], Scheme="internal",
        Type="application", IpAddressType="ipv4", Tags=[{"Key": "Name", "Value": name}],
    )["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _delete_load_balancer(elb, lb_arn))
    elb.create_listener(
        LoadBalancerArn=lb_arn, Protocol="HTTP", Port=80,
        DefaultActions=[{"Type": "fixed-response", "FixedResponseConfig": {
            "StatusCode": "200", "ContentType": "text/plain", "MessageBody": name}}],
    )
    _poll_until(
        lambda: elb.describe_load_balancers(LoadBalancerArns=[lb_arn])
        ["LoadBalancers"][0]["State"]["Code"],
        lambda s: s == "active",
        timeout_s=_ALB_ACTIVE_BUDGET_S, interval_s=10.0, description=f"ALB {name} to become active",
    )

    endpoint_config = {
        "Arn": lb_arn, "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "http-only",
    }
    vpc_origin_ids = []
    ctx.on_cleanup(lambda: _delete_vpc_origins(cf, vpc_origin_ids))
    first_id = cf.create_vpc_origin(
        VpcOriginEndpointConfig={"Name": name, **endpoint_config})["VpcOrigin"]["Id"]
    vpc_origin_ids.append(first_id)

    try:
        cf.create_vpc_origin(VpcOriginEndpointConfig={"Name": name, **endpoint_config})
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    else:
        raise AssertionError(f"a second VPC origin reusing the name {name!r} was accepted")
    assert code == "EntityAlreadyExists", (
        f"expected EntityAlreadyExists for a duplicate VPC origin Name, got {code!r}: {message!r}"
    )
    expected_message = "Another vpc origin with the same name already exists within the aws account."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    other_name = ctx.unique_name("sim2real-vod-other-")
    second_id = cf.create_vpc_origin(
        VpcOriginEndpointConfig={"Name": other_name, **endpoint_config})["VpcOrigin"]["Id"]
    vpc_origin_ids.append(second_id)
    read_back = cf.get_vpc_origin(Id=second_id)["VpcOrigin"]["VpcOriginEndpointConfig"]
    got = (read_back["Name"], read_back["Arn"], read_back["HTTPPort"], read_back["HTTPSPort"],
           read_back["OriginProtocolPolicy"])
    assert got == (other_name, lb_arn, 80, 443, "http-only"), (
        f"GetVpcOrigin read back {got!r} for the VPC origin created under {other_name!r}"
    )

    names = _vpc_origin_names(cf)
    assert names.count(name) == 1, f"expected exactly one VPC origin named {name!r}, got {names!r}"
    assert names.count(other_name) == 1, (
        f"expected exactly one VPC origin named {other_name!r}, got {names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
