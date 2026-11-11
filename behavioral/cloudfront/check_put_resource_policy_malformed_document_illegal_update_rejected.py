"""put-resource-policy-malformed-document-illegal-update-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-resource-policy-malformed-document-illegal-update-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with malformed JSON on a deployed VPC origin is InvalidArgument with the exact
    "policy format isn't valid" message and persists nothing; a well-formed document then succeeds."""
    cf = ctx.client("cloudfront")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    # Wait for Deployed first: a Put on a still-deploying origin is IllegalUpdate before the
    # document is ever validated.
    vpc_origin_arn = _create_vpc_origin(ctx, cf, ec2, ssm)

    malformed_document = "{this is not valid json at all"
    code, message = _error(
        lambda: cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=malformed_document)
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    expected = "The specified policy format isn't valid. Verify that the format is valid JSON and try again."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect-absent: nothing was persisted from the malformed attempt
    absent = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert json.loads(absent["PolicyDocument"]) == {}, (
        f"expected the never-attached empty document, got {absent['PolicyDocument']!r}"
    )

    # positive control: a well-formed document on the same resource succeeds
    good_document = json.dumps(_sample_policy(vpc_origin_arn, ctx.account))
    cf.put_resource_policy(ResourceArn=vpc_origin_arn, PolicyDocument=good_document)
    ctx.on_cleanup(lambda: _best_effort_delete_policy(cf, vpc_origin_arn))

    got = cf.get_resource_policy(ResourceArn=vpc_origin_arn)
    assert got["ResourceArn"] == vpc_origin_arn
    assert json.loads(got["PolicyDocument"]) == json.loads(good_document)


def _sample_policy(resource_arn: str, account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "sim2realCrossAccountRead",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "cloudfront:GetVpcOrigin",
                "Resource": resource_arn,
            }
        ],
    }


def _error(fn):
    """Call fn() and return its botocore (code, message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_vpc_origin(ctx, cf, ec2, ssm) -> str:
    instance_id = _launch_backing_instance(ctx, ec2, ssm)
    ctx.on_cleanup(lambda: _terminate_instance(ec2, instance_id))
    _wait_instance_running(ec2, instance_id)

    sts = ctx.client("sts")
    own_account = sts.get_caller_identity()["Account"]
    region = ec2.meta.region_name
    instance_arn = f"arn:aws:ec2:{region}:{own_account}:instance/{instance_id}"

    origin_name = ctx.unique_name("sim2real-cf-vpcorigin-")
    try:
        created = _create_vpc_origin_with_retry(
            cf,
            {
                "Name": origin_name,
                "Arn": instance_arn,
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "http-only",
            },
        )
    except Exception as exc:  # noqa: BLE001
        from botocore.exceptions import ClientError

        if isinstance(exc, ClientError) and exc.response["Error"]["Code"] == "InternalError":
            raise AssertionError(
                f"CreateVpcOrigin persistently returns InternalError for an "
                f"EC2-instance-backed origin in this account/region: {exc}"
            ) from exc
        raise
    vpc_origin = created["VpcOrigin"]
    vpc_origin_id = vpc_origin["Id"]
    ctx.on_cleanup(lambda: _cleanup_vpc_origin(cf, vpc_origin_id))
    _wait_vpc_origin_deployed(cf, vpc_origin_id, timeout_s=900)
    return vpc_origin["Arn"]


_INSTANCE_TYPE = "t3.micro"


def _select_az_for_instance_type(ec2, instance_type: str) -> str | None:
    """An AZ offering ``instance_type``, or None if the query fails.

    Not every AZ offers every instance type; a blind pick surfaces as run_instances Unsupported."""
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    except Exception:  # noqa: BLE001 - best effort; fall back to unpinned AZ
        return None
    zones = sorted({o["Location"] for o in offerings})
    return zones[0] if zones else None


def _launch_backing_instance(ctx, ec2, ssm):
    ami_id = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]

    vpc_cidr = "10.234.0.0/24"
    vpc_id = ec2.create_vpc(CidrBlock=vpc_cidr)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc_network(ec2, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    az = _select_az_for_instance_type(ec2, _INSTANCE_TYPE)
    subnet_kwargs = {"VpcId": vpc_id, "CidrBlock": vpc_cidr}
    if az is not None:
        subnet_kwargs["AvailabilityZone"] = az
    subnet_id = ec2.create_subnet(**subnet_kwargs)["Subnet"]["SubnetId"]
    ec2.get_waiter("subnet_available").wait(SubnetIds=[subnet_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    name = ctx.unique_name("sim2real-cf-vpcorigin-backing-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType=_INSTANCE_TYPE,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    return resp["Instances"][0]["InstanceId"]


def _delete_vpc_network(ec2, vpc_id):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
            for subnet in subnets:
                _delete_net(ec2, "delete_subnet", SubnetId=subnet["SubnetId"])
            igws = ec2.describe_internet_gateways(
                Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
            )["InternetGateways"]
            for igw in igws:
                _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw["InternetGatewayId"], VpcId=vpc_id)
                _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw["InternetGatewayId"])
            _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code == "DependencyViolation":
                time.sleep(10)
                continue
            raise
    raise AssertionError(f"could not tear down vpc {vpc_id} within 180s (DependencyViolation persisted)")


def _terminate_instance(ec2, instance_id):
    ec2.terminate_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _wait_instance_running(ec2, instance_id, timeout_s=120, interval_s=5):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            desc = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError:
            time.sleep(interval_s)
            continue
        state = desc["Reservations"][0]["Instances"][0]["State"]["Name"]
        if state == "running":
            return state
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} did not reach running within {timeout_s}s (last={state})")


def _create_vpc_origin_with_retry(cf, endpoint_config, attempts=3, base_delay_s=6):
    from botocore.exceptions import ClientError

    last_exc = None
    for attempt in range(attempts):
        try:
            return cf.create_vpc_origin(VpcOriginEndpointConfig=endpoint_config)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InternalError", "Throttling", "TooManyRequests"):
                raise
            last_exc = exc
            time.sleep(base_delay_s * (attempt + 1))
    raise last_exc


def _wait_vpc_origin_deployed(cf, vpc_origin_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_vpc_origin(Id=vpc_origin_id)["VpcOrigin"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"vpc origin {vpc_origin_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_vpc_origin(cf, vpc_origin_id):
    from botocore.exceptions import ClientError

    try:
        cf.delete_resource_policy(ResourceArn=cf.get_vpc_origin(Id=vpc_origin_id)["VpcOrigin"]["Arn"])
    except ClientError as err:
        if err.response["Error"]["Code"] != "EntityNotFound":
            raise

    try:
        cf.get_vpc_origin(Id=vpc_origin_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchVpcOrigin", "EntityNotFound"):
            return
        raise
    _wait_vpc_origin_deployed(cf, vpc_origin_id)
    etag = cf.get_vpc_origin(Id=vpc_origin_id)["ETag"]
    try:
        cf.delete_vpc_origin(Id=vpc_origin_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("NoSuchVpcOrigin", "EntityNotFound"):
            return
        raise


def _best_effort_delete_policy(cf, resource_arn) -> None:
    try:
        cf.delete_resource_policy(ResourceArn=resource_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


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
