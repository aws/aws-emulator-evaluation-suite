"""resource-policy-put-illegal-update-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-policy-put-illegal-update-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy whose statement Resource differs from ResourceArn fails InvalidArgument.

    No policy is persisted; the same call with a matching Resource is accepted and retrievable.
    """
    cf = ctx.client("cloudfront")
    origin = _create_vpc_origin(ctx)
    # A fabricated Principal account is itself rejected with InvalidArgument
    # ("references a principal that doesn't exist"), which would collapse into
    # the same error code as the Resource-mismatch we mean to test. Use the
    # check's own real caller identity so the only broken thing is the mismatch.
    principal_account = ctx.client("sts").get_caller_identity()["Account"]

    # Break exactly one thing: the statement's Resource points at a DIFFERENT
    # (fabricated, never-existing) VPC origin ARN than the one named in the
    # ResourceArn request parameter. AWS answers this mismatch with InvalidArgument, not
    # IllegalUpdate.
    mismatched_resource = origin["arn"].rsplit("/", 1)[0] + "/VOmismatched00000000"
    bad_policy = _build_policy(mismatched_resource, "cloudfront:GetVpcOrigin", principal_account)

    code, message = _error(
        lambda: cf.put_resource_policy(
            ResourceArn=origin["arn"], PolicyDocument=json.dumps(bad_policy)
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    expected = (
        "The specified policy isn't valid (InvalidPolicy). Verify that it's both valid JSON, "
        "and that the ARN specified in the policy is the same ARN in the ResourceARN parameter"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect must be absent: no policy was ever attached to the resource. A VPC
    # origin ARN that has never had a policy attached answers GetResourcePolicy
    # with 200 and an EMPTY PolicyDocument -- EntityNotFound is reserved for a
    # policy that existed and was then deleted, which is not this case.
    absent = cf.get_resource_policy(ResourceArn=origin["arn"])
    assert _as_json(absent["PolicyDocument"]) == {}, (
        f"expected an empty PolicyDocument (no policy ever attached), "
        f"got {absent['PolicyDocument']!r}"
    )

    # Positive control: the identical operation, same resource, with a document
    # whose Resource actually matches ResourceArn is accepted and retrievable --
    # without this, "rejects a Resource/ResourceArn mismatch" is indistinguishable
    # from "PutResourcePolicy always fails".
    good_policy = _build_policy(origin["arn"], "cloudfront:GetVpcOrigin", principal_account)
    cf.put_resource_policy(ResourceArn=origin["arn"], PolicyDocument=json.dumps(good_policy))
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cf.delete_resource_policy(ResourceArn=origin["arn"])))
    stored = _as_json(cf.get_resource_policy(ResourceArn=origin["arn"])["PolicyDocument"])
    assert stored == good_policy, f"expected stored policy {good_policy!r}, got {stored!r}"


# ===== helpers =====


def _as_json(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value


def _build_policy(resource_arn: str, action: str, principal_account: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "CrossAccountGrant",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{principal_account}:root"},
                "Action": action,
                "Resource": resource_arn,
            }
        ],
    }


def _error(fn) -> tuple[str, str | None]:
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING input AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED: {result!r}")


def _create_vpc_origin(ctx) -> dict[str, str]:
    """A VPC origin over a minimal internal ALB: CloudFront resource policies accept only a VPC
    origin ARN, and CreateVpcOrigin rejects a fabricated ALB ARN with LoadBalancerNotFound.
    The ALB needs only a real ARN (two subnets in different AZs), never a Deployed state."""
    ec2 = ctx.client("ec2")
    elbv2 = ctx.client("elbv2")
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-vpco-")

    vpc = ec2.create_vpc(
        CidrBlock="10.198.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id)
        )
    )

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.198.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": f"{name}-{i}"}]}
            ],
        )["Subnet"]
        sid = subnet["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _ignore_not_found(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))

    sg = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral probe SG",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: _delete_net(ec2, "delete_security_group", GroupId=sg_id)))

    lb = elbv2.create_load_balancer(
        Name=name,
        Subnets=subnet_ids,
        SecurityGroups=[sg_id],
        Scheme="internal",
        Type="application",
        IpAddressType="ipv4",
        Tags=[{"Key": "Name", "Value": name}],
    )["LoadBalancers"][0]
    lb_arn = lb["LoadBalancerArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: elbv2.delete_load_balancer(LoadBalancerArn=lb_arn)))

    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig={
            "Name": name,
            "Arn": lb_arn,
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
        },
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    vpc_origin = resp["VpcOrigin"]
    vo_id = vpc_origin["Id"]
    arn = vpc_origin["Arn"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, vo_id))

    # PutResourcePolicy/GetResourcePolicy reject a VPC origin that hasn't finished
    # deploying with IllegalUpdate ("wasn't successfully deployed") -- a real,
    # timing-dependent state the resource-mismatch test must not race. Wait for it
    # to leave "Deploying" before the check makes any resource-policy call.
    deadline = time.monotonic() + 900.0
    status = vpc_origin["Status"]
    while time.monotonic() < deadline:
        if status != "Deploying":
            break
        time.sleep(2)
        status = cf.get_vpc_origin(Id=vo_id)["VpcOrigin"]["Status"]
    if status == "Deploying":
        raise AssertionError(f"vpc origin {vo_id} never left Deploying within 900s")

    return {"id": vo_id, "arn": arn}


# Not-found codes of the teardown calls: the resource is already gone.
_NOT_FOUND = (
    "EntityNotFound", "NoSuchResource", "InvalidVpcID.NotFound", "InvalidInternetGatewayID.NotFound",
    "Gateway.NotAttached", "InvalidSubnetID.NotFound", "InvalidGroup.NotFound", "LoadBalancerNotFound",
)


def _ignore_not_found(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _NOT_FOUND:
            raise


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
    raise AssertionError(f"DeleteVpcOrigin({vo_id}) still refused after 120 s of retries")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. So wait (bounded) for the ENIs to
# go, retry DependencyViolation inside the same window, and raise a final failure naming the ENIs
# still attached. The window is shared by all of one check's network deletes.
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

