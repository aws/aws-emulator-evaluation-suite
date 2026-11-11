"""resource-policy-json-document-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-json-document-round-trip"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A nested resource policy round-trips through GetResourcePolicy except that a one-item Action list
    reads back as a bare string; adding a Condition block is InvalidArgument and changes nothing."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resource_arn = _create_vpc_origin_resource_arn(ctx)

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SharedReadAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["cloudfront:GetVpcOrigin"],
                "Resource": resource_arn,
            }
        ],
    }
    cf.put_resource_policy(ResourceArn=resource_arn, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: cf.delete_resource_policy(ResourceArn=resource_arn))

    read_back = json.loads(cf.get_resource_policy(ResourceArn=resource_arn)["PolicyDocument"])
    statement = read_back["Statement"][0]
    # CloudFront collapses a single-item Action list to a bare string on read-back.
    assert statement["Action"] == "cloudfront:GetVpcOrigin", (
        f"expected Action to collapse to a bare string on read-back, got {statement['Action']!r}"
    )
    expected = {
        **policy_doc,
        "Statement": [{**policy_doc["Statement"][0], "Action": "cloudfront:GetVpcOrigin"}],
    }
    assert read_back == expected, f"expected {expected!r}, got {read_back!r}"

    # CloudFront's VPC-origin resource-policy dialect rejects any Condition block outright.
    with_condition = json.loads(json.dumps(policy_doc))
    with_condition["Statement"][0]["Condition"] = {"StringEquals": {"aws:SourceAccount": account_id}}
    code, message = _error(lambda: cf.put_resource_policy(
        ResourceArn=resource_arn, PolicyDocument=json.dumps(with_condition)
    ))
    assert code == "InvalidArgument", f"expected InvalidArgument for a Condition block, got {code!r}"
    expected_message = (
        "The specified policy isn't valid (InvalidPolicy). Verify that it's both valid JSON, "
        "and that the ARN specified in the policy is the same ARN in the ResourceARN parameter"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    unchanged = json.loads(cf.get_resource_policy(ResourceArn=resource_arn)["PolicyDocument"])
    assert unchanged == expected, f"rejected update must not change the stored policy, got {unchanged!r}"


def _error(fn):
    """Call fn() and return its botocore (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    return value


def _create_vpc_origin_resource_arn(ctx) -> str:
    """Wrap an internal ALB in a VPC origin and return the origin's ARN.

    A VPC origin is the only resource type PutResourcePolicy accepts."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    cf = ctx.client("cloudfront")

    vpc_id, subnet_ids = _adopt_or_create_vpc_with_subnets(ctx, ec2)

    sg_name = ctx.unique_name("sim2real-vpcorigin-sg")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real vpc-origin test sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": sg_name}]}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group(ec2, sg_id))

    alb_name = ctx.unique_name("sim2real-vpcorigin")[:32].rstrip("-")
    alb_resp = elbv2.create_load_balancer(
        Name=alb_name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": alb_name}],
    )
    alb_arn = alb_resp["LoadBalancers"][0]["LoadBalancerArn"]
    ctx.on_cleanup(lambda: elbv2.delete_load_balancer(LoadBalancerArn=alb_arn))

    elbv2.get_waiter("load_balancer_available").wait(
        LoadBalancerArns=[alb_arn], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    vpc_origin_name = ctx.unique_name("sim2real-vpcorigin")
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

    deployed = _poll_until(
        lambda: cf.get_vpc_origin(Id=vpc_origin_id)["VpcOrigin"],
        lambda v: v["Status"] != "Deploying",
        timeout_s=900,
        interval_s=15,
    )
    if deployed["Status"] != "Deployed":
        raise AssertionError(
            f"VPC origin never reached Deployed (status={deployed['Status']!r})",
        )

    return deployed["Arn"]


# Zone IDs where CloudFront does not support VPC origins (CloudFront Developer Guide, "Supported AWS
# Regions for VPC origins"); zone IDs, unlike zone names, are the same in every account.
_VPC_ORIGIN_UNSUPPORTED_ZONE_IDS = frozenset({"use1-az3", "usw1-az2", "apne1-az3", "cac1-az3"})


def _adopt_or_create_vpc_with_subnets(ctx, ec2) -> tuple[str, list[str]]:
    """Use the check's network if its subnets span >=2 supported AZs, else create a VPC with 2 subnets.

    Cleanups here register before the SG/ALB/origin ones, so LIFO teardown deletes the network last."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            if s.get("AvailabilityZoneId") in _VPC_ORIGIN_UNSUPPORTED_ZONE_IDS:
                continue
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())[:2]
        if len(subnet_ids) >= 2:
            return vpc_id, subnet_ids

    tag_name = ctx.unique_name("sim2real-vpcorigin-net-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.174.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tag_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    azs = [
        az
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if az.get("ZoneId") not in _VPC_ORIGIN_UNSUPPORTED_ZONE_IDS
    ]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region!r} does not have 2 available AZs to host an ALB")

    subnet_ids = []
    for i, (cidr, az) in enumerate(
        zip(["10.174.1.0/24", "10.174.2.0/24"], (azs[0]["ZoneName"], azs[1]["ZoneName"]))
    ):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=cidr,
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{tag_name}-{i}"}]}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))

    return vpc_id, subnet_ids


def _delete_vpc_origin(cf, vpc_origin_id: str) -> None:
    try:
        got = cf.get_vpc_origin(Id=vpc_origin_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    etag = got["ETag"]
    status = got["VpcOrigin"]["Status"]
    deadline = time.monotonic() + 900
    while status == "Deploying" and time.monotonic() < deadline:
        time.sleep(15)
        got = cf.get_vpc_origin(Id=vpc_origin_id)
        etag = got["ETag"]
        status = got["VpcOrigin"]["Status"]
    try:
        cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            cf.get_vpc_origin(Id=vpc_origin_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        time.sleep(15)
    raise AssertionError(f"VPC origin {vpc_origin_id} still exists 900 s after DeleteVpcOrigin")


def _delete_security_group(ec2, sg_id: str) -> None:
    deadline = time.monotonic() + 300
    while True:
        try:
            _delete_net(ec2, "delete_security_group", GroupId=sg_id)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidGroup.NotFound":
                return
            if time.monotonic() >= deadline:
                raise
            time.sleep(10)


# A load balancer, endpoint or instance in this VPC deletes asynchronously and leaves its ENIs
# behind briefly, so DeleteSubnet / DeleteSecurityGroup / DeleteVpc fail with DependencyViolation.
# Wait (bounded) for the ENIs to go and retry, then fail naming the ENIs still attached.
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

