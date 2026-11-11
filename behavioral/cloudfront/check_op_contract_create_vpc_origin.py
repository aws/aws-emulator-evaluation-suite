"""op-contract-createVpcOrigin."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createVpcOrigin"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcOrigin wraps a real EC2 instance ARN as an origin endpoint, and a duplicate Name is
    rejected without creating a second origin.
    """
    instance_arn = _launch_probe_instance(ctx)
    cf = ctx.client("cloudfront")

    name = ctx.unique_name("sim2real-vpcorigin-")
    endpoint_config = {
        "Name": name,
        "Arn": instance_arn,
        "HTTPPort": 80,
        "HTTPSPort": 443,
        "OriginProtocolPolicy": "http-only",
    }
    resp = cf.create_vpc_origin(
        VpcOriginEndpointConfig=endpoint_config,
        Tags={
            "Items": [
                {"Key": "Name", "Value": name},
                {"Key": "sim2real:managed", "Value": "true"},
            ]
        },
    )
    origin = resp["VpcOrigin"]
    origin_id = origin["Id"]
    ctx.on_cleanup(lambda: _delete_vpc_origin(ctx, origin_id))

    assert origin_id, "expected a non-empty VpcOrigin Id"
    assert origin["Status"], "expected a non-empty Status"
    assert origin["Arn"], "expected a non-empty VpcOrigin Arn"
    assert origin["VpcOriginEndpointConfig"]["Arn"] == instance_arn, (
        f"expected config Arn {instance_arn!r}, got {origin['VpcOriginEndpointConfig']['Arn']!r}"
    )
    assert origin["VpcOriginEndpointConfig"]["Name"] == name, (
        f"expected config Name {name!r}, got {origin['VpcOriginEndpointConfig']['Name']!r}"
    )
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    got = cf.get_vpc_origin(Id=origin_id)["VpcOrigin"]
    assert got["Id"] == origin_id, f"independent read returned Id {got['Id']!r}, expected {origin_id!r}"
    assert got["VpcOriginEndpointConfig"]["Arn"] == instance_arn, (
        f"independent read returned config Arn {got['VpcOriginEndpointConfig']['Arn']!r}, expected {instance_arn!r}"
    )

    # Distinct error boundary: a second VPC origin with the same Name is rejected, and the failed
    # attempt does not leave a second resource behind (effect absent, on an independent read).
    code, message = _error(
        lambda: cf.create_vpc_origin(
            VpcOriginEndpointConfig={**endpoint_config}
        )
    )
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code}"
    assert message == "Another vpc origin with the same name already exists within the aws account.", (
        f"expected the exact refusal message, got {message!r}"
    )

    listed = cf.list_vpc_origins()
    matching = [i for i in listed.get("VpcOriginList", {}).get("Items", []) if i["Name"] == name]
    assert len(matching) == 1, (
        f"expected exactly 1 VPC origin named {name!r} after the rejected duplicate, got {len(matching)}"
    )
    assert matching[0]["Id"] == origin_id, (
        f"the surviving VPC origin named {name!r} has Id {matching[0]['Id']!r}, expected {origin_id!r}"
    )

    # CloudFront refuses to delete a VPC origin until it is Deployed, and the teardown budget is
    # too short to cover both the deployment and the deletion, so the deployment is waited out here.
    _wait_vpc_origin_deployed(cf, origin_id)


def _launch_probe_instance(ctx) -> str:
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    ssm = ctx.client("ssm")

    offered = ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": ["t3.micro"]}, {"Name": "location", "Values": ctx.network().availability_zones}],
    )["InstanceTypeOfferings"]
    zones = {o["Location"] for o in offered}
    subnets = [
        s
        for s in ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        if s["AvailabilityZone"] in zones
    ]
    if not subnets:
        raise AssertionError("no shared network VPC subnet in a t3.micro zone to host a VPC-origin probe instance")
    subnet = subnets[0]
    vpc_id = subnet["VpcId"]

    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("no default security group available for a VPC-origin probe instance")

    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]

    name = ctx.unique_name("sim2real-vpco-probe-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["SubnetId"],
        SecurityGroupIds=[sgs[0]["GroupId"]],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [
                    {"Key": "Name", "Value": name},
                    {"Key": "sim2real:managed", "Value": "true"},
                ],
            }
        ],
    )
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id],
        WaiterConfig={"Delay": 2, "MaxAttempts": 60},
    )

    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:ec2:{ctx.region}:{account_id}:instance/{instance_id}"


def _wait_vpc_origin_deployed(cf, origin_id: str, timeout_s: float = 1200.0, interval_s: float = 15.0) -> None:
    import time

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_vpc_origin(Id=origin_id)["VpcOrigin"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"VPC origin {origin_id!r} still {status!r} after {timeout_s:.0f}s")


def _delete_vpc_origin(ctx, origin_id: str, timeout_s: float = 600.0, interval_s: float = 15.0) -> None:
    """Delete the VPC origin once CloudFront accepts it (it refuses while still deploying), then
    wait until it is gone. Raises on timeout so a leaked origin is never silent."""
    import time

    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            info = cf.get_vpc_origin(Id=origin_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "EntityNotFound":
                return
            raise
        if info["VpcOrigin"]["Status"] == "Deployed":
            try:
                cf.delete_vpc_origin(Id=origin_id, IfMatch=info["ETag"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "EntityNotFound":
                    return
        time.sleep(interval_s)
    raise AssertionError(f"VPC origin {origin_id!r} still present after {timeout_s:.0f}s of teardown")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises,
    so a call AWS refuses is never read as a mere code mismatch.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
