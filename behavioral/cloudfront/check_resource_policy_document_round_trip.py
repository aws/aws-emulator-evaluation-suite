"""resource-policy-document-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "resource-policy-document-round-trip"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A JSON resource policy attached to a CloudFront VPC origin via PutResourcePolicy,
    including a nested unicode string, comes back byte-identical (as parsed JSON) from
    GetResourcePolicy."""
    cf = ctx.client("cloudfront")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    instance_arn = _launch_vpc_origin_target(ctx)
    try:
        vpc_origin = cf.create_vpc_origin(
            VpcOriginEndpointConfig={
                "Name": ctx.unique_name("sim2real-vpco-")[:64],
                "Arn": instance_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
            }
        )["VpcOrigin"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InternalError":
            raise AssertionError(
                "CreateVpcOrigin persistently returns InternalError for an "
                "EC2-instance-backed origin in this account/region; cannot exercise "
                "PutResourcePolicy on a VPC origin here"
            ) from exc
        raise
    vpc_origin_id = vpc_origin["Id"]
    vpc_origin_arn = vpc_origin["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin_best_effort(ctx, vpc_origin_id))
    _wait_vpc_origin_deployed(ctx, vpc_origin_id)

    unicode_sid = "sim2real-Access-\u4e16\u754c-\U0001f680"
    policy = {
        "Version": "2008-10-17",
        "Statement": [
            {
                "Sid": unicode_sid,
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "cloudfront:GetVpcOrigin",
                "Resource": vpc_origin_arn,
            }
        ],
    }
    policy_document = json.dumps(policy, ensure_ascii=False)

    cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=policy_document)
    ctx.on_cleanup(
        lambda: _try(
            lambda: cf.delete_resource_policy(ResourceArn=vpc_origin_arn),
            not_found_codes=("EntityNotFound",),
        )
    )

    got = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    got_policy = json.loads(got["PolicyDocument"])
    assert got_policy == policy, f"expected {policy!r}, got {got_policy!r}"
    assert got_policy["Statement"][0]["Sid"] == unicode_sid, (
        f"expected Sid {unicode_sid!r}, got {got_policy['Statement'][0].get('Sid')!r}"
    )


def _try(fn, *, not_found_codes: tuple[str, ...] = ()) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in not_found_codes:
            raise


def _launch_vpc_origin_target(ctx) -> str:
    """Launch an EC2 instance in a new VPC with an internet gateway and return its ARN.

    Cleanups are registered in creation order so LIFO teardown unwinds them safely."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.83.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cf-vpco-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(
        lambda: _try(
            lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id),
            not_found_codes=("InvalidVpcID.NotFound",),
        )
    )

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cf-igw-")}]}
        ]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _cleanup_igw():
        _try(
            lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id),
            not_found_codes=("InvalidInternetGatewayID.NotFound", "Gateway.NotAttached"),
        )
        _try(
            lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id),
            not_found_codes=("InvalidInternetGatewayID.NotFound",),
        )

    ctx.on_cleanup(_cleanup_igw)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.83.1.0/24",
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cf-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(
        lambda: _try(
            lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id),
            not_found_codes=("InvalidSubnetID.NotFound",),
        )
    )

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    instance_id = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cf-origin-")}]}
        ],
    )["Instances"][0]["InstanceId"]

    def _cleanup_instance():
        _try(
            lambda: ec2.terminate_instances(InstanceIds=[instance_id]),
            not_found_codes=("InvalidInstanceID.NotFound",),
        )
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            try:
                state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
                    "Instances"
                ][0]["State"]["Name"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                    raise
                return
            if state == "terminated":
                return
            time.sleep(10)

    ctx.on_cleanup(_cleanup_instance)

    deadline = time.monotonic() + 90.0
    state = "pending"
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0][
                "Instances"
            ][0]["State"]["Name"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                # brief eventual-consistency window right after RunInstances
                time.sleep(5)
                continue
            raise
        if state == "running":
            break
        time.sleep(2)
    if state != "running":
        raise AssertionError(
            f"EC2 instance did not reach running state within the check's time budget "
            f"(last observed: {state}); cannot exercise a VPC-origin-backed "
            "PutResourcePolicy here",
        )

    return f"arn:aws:ec2:{ctx.region}:{ctx.client('sts').get_caller_identity()['Account']}:instance/{instance_id}"


def _wait_vpc_origin_deployed(ctx, vpc_origin_id: str, timeout_s: float = 1500.0) -> None:
    """Poll until the VPC origin is Deployed, which PutResourcePolicy requires.

    An instance-backed VPC origin can take up to ~1500 s to deploy."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = cf.get_vpc_origin(Id=vpc_origin_id)
        if got["VpcOrigin"]["Status"] == "Deployed":
            return
        time.sleep(2)
    raise AssertionError(
        "VPC origin did not reach Deployed status within the check's time budget; "
        "cannot exercise PutResourcePolicy on it here",
    )


def _delete_vpc_origin_best_effort(ctx, vpc_origin_id: str, timeout_s: float = 900.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            got = cf.get_vpc_origin(Id=vpc_origin_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        if got["VpcOrigin"]["Status"] == "Deployed":
            try:
                cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=got["ETag"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFound":
                    raise
            return
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
