"""put-resource-policy-concurrent-overwrite-last-writer-wins."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-concurrent-overwrite-last-writer-wins"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two sequential PutResourcePolicy calls on one VPC origin: the second document fully replaces
    the first (last writer wins), with no merge."""
    cf = ctx.client("cloudfront")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    principal_arn = f"arn:aws:iam::{account_id}:root"

    origin_arn = _create_vpc_origin(ctx)

    policy_v1 = _policy_doc(principal_arn, origin_arn, "sim2real-v1")
    policy_v2 = _policy_doc(principal_arn, origin_arn, "sim2real-v2")

    cf.put_resource_policy(ResourceArn=origin_arn, PolicyDocument=json.dumps(policy_v1))
    ctx.on_cleanup(lambda: _delete_policy_safe(cf, origin_arn))

    first = cf.get_resource_policy(ResourceArn=origin_arn)
    first_doc = _as_doc(first["PolicyDocument"])
    assert first_doc["Statement"][0]["Sid"] == "sim2real-v1", (
        f"expected first PutResourcePolicy to be visible as sim2real-v1, got {first_doc!r}"
    )

    # A second, sequential write from another caller must fully overwrite the first.
    cf.put_resource_policy(ResourceArn=origin_arn, PolicyDocument=json.dumps(policy_v2))

    second = cf.get_resource_policy(ResourceArn=origin_arn)
    second_doc = _as_doc(second["PolicyDocument"])
    assert len(second_doc["Statement"]) == 1, f"expected a clean overwrite, not a merge: {second_doc!r}"
    assert second_doc["Statement"][0]["Sid"] == "sim2real-v2", (
        f"expected second PutResourcePolicy to fully replace the first, got {second_doc!r}"
    )
    assert second_doc != first_doc, "expected the stored document to change after the second Put"


def _policy_doc(principal_arn, resource_arn, sid):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "cloudfront:GetVpcOrigin",
                "Resource": resource_arn,
            }
        ],
    }


def _as_doc(value):
    if isinstance(value, str):
        return json.loads(value)
    return value


def _delete_policy_safe(cf, resource_arn):
    try:
        cf.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


#: Not-found codes a network teardown treats as already deleted.
_GONE = ("InvalidVpcID.NotFound", "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached",
         "InvalidSubnetID.NotFound", "InvalidGroup.NotFound", "LoadBalancerNotFound")


def _ignore_gone(fn) -> None:
    """Run a teardown call; an already-deleted resource is done, every other failure raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE:
            raise


def _create_vpc_origin(ctx) -> str:
    """Build an internal ALB in a dedicated VPC and wrap it in a VPC origin, returning its ARN.

    PutResourcePolicy accepts only VPC origin ARNs, and CreateVpcOrigin requires a real ALB.
    PutResourcePolicy on a not-yet-Deployed origin is IllegalUpdate, so this waits for Deployed."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-vpco-")
    name_tag = [{"Key": "Name", "Value": name}]

    vpc = ec2.create_vpc(
        CidrBlock="10.199.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": name_tag}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _ignore_gone(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[{"ResourceType": "internet-gateway", "Tags": name_tag}],
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _ignore_gone(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id)))
    ctx.on_cleanup(lambda: _ignore_gone(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)))

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.199.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": name_tag}],
        )["Subnet"]
        sid = subnet["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _ignore_gone(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))

    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral probe SG",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": name_tag}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _ignore_gone(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))

    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=name_tag,
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_gone(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))

    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": name,
            "Arn": lb_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
        }
    )
    vpc_origin = resp["VpcOrigin"]
    vo_id = vpc_origin["Id"]
    arn = vpc_origin["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vo_id))
    _wait_vpc_origin_deployed(cf, vo_id)
    return arn


def _wait_vpc_origin_deployed(cf, vo_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_vpc_origin(Id=vo_id)["VpcOrigin"]["Status"]
        if status == "Deployed":
            return
        if status == "Failed":
            raise AssertionError(f"vpc origin {vo_id} reached Failed while waiting for Deployed")
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vo_id} did not reach Deployed within {timeout_s}s (last={status})")


def _delete_vpc_origin(ctx, vo_id: str, timeout_s: float = 600.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        try:
            current = cf.get_vpc_origin(Id=vo_id)
        except ClientError as err:
            if err.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        etag = current["ETag"]
        status = current["VpcOrigin"]["Status"]
        if status not in ("Creating", "InProgress", "Deploying"):
            break
        time.sleep(2)
    if etag is None:
        return
    # A stale ETag, a still-deploying origin (IllegalDelete) or a lingering reference (...InUse)
    # clears on its own: re-read the ETag and retry to a deadline.
    delete_deadline = time.monotonic() + 120.0
    while time.monotonic() < delete_deadline:
        try:
            cf.delete_vpc_origin(Id=vo_id, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFound":
                return
            if (code not in ("InvalidIfMatchVersion", "PreconditionFailed", "IllegalDelete")
                    and "InUse" not in code):
                raise
        time.sleep(2)
        try:
            etag = cf.get_vpc_origin(Id=vo_id)["ETag"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
    raise AssertionError(f"vpc origin {vo_id} still not deleted after 120 s of DeleteVpcOrigin retries")


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
