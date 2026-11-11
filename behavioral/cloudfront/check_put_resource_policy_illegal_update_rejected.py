"""put-resource-policy-illegal-update-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-resource-policy-illegal-update-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a grant of a mutating action on a VPC origin with InvalidArgument
    (not IllegalUpdate) and stores nothing; the same grant of a read-only action is stored."""
    cf = ctx.client("cloudfront")
    resource_arn = _create_vpc_origin_resource_arn(ctx)
    ctx.on_cleanup(lambda: _delete_resource_policy_if_present(cf, resource_arn))

    # PutResourcePolicy rejects a nonexistent principal account with InvalidArgument, which
    # would mask the action-type rule, so grant to the caller's own account.
    principal_account = ctx.client("sts").get_caller_identity()["Account"]

    disallowed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DisallowedMutatingAction",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account}:root"},
                "Action": ["cloudfront:DeleteVpcOrigin"],
                "Resource": resource_arn,
            }
        ],
    }
    code, message = _error(lambda: cf.put_resource_policy(
        ResourceArn=resource_arn, PolicyDocument=_dumps(disallowed_policy)
    ))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r} (message={message!r})"
    expected = (
        "The specified policy isn't valid (InvalidPolicy). Verify that it's both valid JSON, "
        "and that the ARN specified in the policy is the same ARN in the ResourceARN parameter"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: a VPC origin with no policy answers GetResourcePolicy with 200 and "{}",
    # not EntityNotFound.
    absent = cf.get_resource_policy(ResourceArn=resource_arn)
    assert _loads(absent["PolicyDocument"]) == {}, (
        f"expected the never-attached empty document, got {absent['PolicyDocument']!r}"
    )

    # Positive control: the same principal/resource with an allowed read-only action succeeds.
    allowed_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowedReadOnlyAction",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account}:root"},
                "Action": "cloudfront:GetVpcOrigin",
                "Resource": resource_arn,
            }
        ],
    }
    cf.put_resource_policy(ResourceArn=resource_arn, PolicyDocument=_dumps(allowed_policy))
    stored = _loads(cf.get_resource_policy(ResourceArn=resource_arn)["PolicyDocument"])
    assert stored == allowed_policy, f"expected stored policy {allowed_policy!r}, got {stored!r}"


def _dumps(obj) -> str:
    import json

    return json.dumps(obj)


def _loads(text: str):
    import json

    return json.loads(text)


def _error(fn):
    """Call fn() and return its botocore (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_resource_policy_if_present(cf, resource_arn: str) -> None:
    try:
        cf.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return


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
    """Wrap an internal ALB in a new VPC in a VPC origin and return the origin's ARN.

    A VPC origin is the only resource type PutResourcePolicy accepts."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    cf = ctx.client("cloudfront")

    net_name = ctx.unique_name("sim2real-vpcorigin-net")

    def _tag_spec(resource_type: str) -> list:
        return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": net_name}]}]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.201.0.0/16", TagSpecifications=_tag_spec("vpc")
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    # CreateVpcOrigin requires an internet gateway in the ALB's VPC, even for an internal ALB.
    igw_id = ec2.create_internet_gateway(
        TagSpecifications=_tag_spec("internet-gateway")
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_internet_gateway(ec2, igw_id, vpc_id))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    if len(azs) < 2:
        raise AssertionError("region lacks >=2 availability zones required for an ALB")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.201.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=_tag_spec("subnet"),
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda subnet_id=subnet_id: _delete_subnet(ec2, subnet_id))

    sg_name = ctx.unique_name("sim2real-vpcorigin-sg")
    sg_id = ec2.create_security_group(
        GroupName=sg_name,
        Description="sim2real vpc-origin test sg",
        VpcId=vpc_id,
        TagSpecifications=_tag_spec("security-group"),
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
        Tags=[{"Key": "Name", "Value": net_name}],
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
        }
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


def _delete_tolerating(ec2, op: str, missing: tuple[str, ...], **ident) -> None:
    """Teardown: one network delete through _delete_net (which waits out DependencyViolation),
    tolerating only the listed not-found codes."""
    try:
        _delete_net(ec2, op, **ident)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in missing:
            raise


def _delete_security_group(ec2, sg_id: str) -> None:
    _delete_tolerating(ec2, "delete_security_group", ("InvalidGroup.NotFound",), GroupId=sg_id)


def _delete_subnet(ec2, subnet_id: str) -> None:
    _delete_tolerating(ec2, "delete_subnet", ("InvalidSubnetID.NotFound",), SubnetId=subnet_id)


def _delete_vpc(ec2, vpc_id: str) -> None:
    _delete_tolerating(ec2, "delete_vpc", ("InvalidVpcID.NotFound",), VpcId=vpc_id)


def _delete_internet_gateway(ec2, igw_id: str, vpc_id: str) -> None:
    _delete_tolerating(
        ec2,
        "detach_internet_gateway",
        ("Gateway.NotAttached", "InvalidInternetGatewayID.NotFound"),
        InternetGatewayId=igw_id,
        VpcId=vpc_id,
    )
    _delete_tolerating(
        ec2,
        "delete_internet_gateway",
        ("InvalidInternetGatewayID.NotFound",),
        InternetGatewayId=igw_id,
    )


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
        _time.sleep(2)
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
        _time.sleep(2)


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
