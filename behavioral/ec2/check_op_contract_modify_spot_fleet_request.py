"""op-contract-modify-spot-fleet-request."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-spot-fleet-request"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifySpotFleetRequest: scaling TargetCapacity down is reflected on
    DescribeSpotFleetRequests, and a nonexistent fleet request id is rejected."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    role_name = ctx.unique_name("sim2real-behav-spotfleet-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "spotfleet.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole",
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole",
        )
    )

    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)
    ami_id = _latest_amazon_linux_ami(ctx)

    config = {
        "IamFleetRole": role_arn,
        "AllocationStrategy": "lowestPrice",
        "TargetCapacity": 1,
        "Type": "maintain",
        "LaunchSpecifications": [
            {"ImageId": ami_id, "InstanceType": "t3.micro", "SubnetId": subnet_id}
        ],
    }

    sfr_id = None
    deadline = time.monotonic() + 60
    last_err = None
    while time.monotonic() < deadline and sfr_id is None:
        try:
            sfr_id = ec2.request_spot_fleet(SpotFleetRequestConfig=config)["SpotFleetRequestId"]
        except Exception as e:  # IAM role propagation delay
            last_err = e
            time.sleep(5)
    if sfr_id is None:
        raise AssertionError(f"could not create spot fleet request (IAM propagation?): {last_err}")
    ctx.on_cleanup(lambda: ec2.cancel_spot_fleet_requests(SpotFleetRequestIds=[sfr_id], TerminateInstances=True))

    _poll_until(
        lambda: ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[sfr_id])["SpotFleetRequestConfigs"][0],
        lambda r: r["SpotFleetRequestState"] in ("active", "failed"),
        timeout_s=90,
    )
    state = ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[sfr_id])["SpotFleetRequestConfigs"][0]
    assert state["SpotFleetRequestState"] == "active", state

    # success path: scale target capacity down to 0. Applying a reduced target
    # capacity to an already-active Spot Fleet request can take several minutes on
    # real AWS (the fleet must reconcile capacity before the config reflects the new
    # value), so allow a generous bounded poll rather than the tight 60s window.
    ec2.modify_spot_fleet_request(SpotFleetRequestId=sfr_id, TargetCapacity=0)
    updated = _poll_until(
        lambda: ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[sfr_id])["SpotFleetRequestConfigs"][0],
        lambda r: r["SpotFleetRequestConfig"]["TargetCapacity"] == 0,
        timeout_s=300,
        interval_s=5,
    )
    assert updated["SpotFleetRequestConfig"]["TargetCapacity"] == 0, updated

    # error boundary
    err, err_message = _client_error(
        lambda: ec2.modify_spot_fleet_request(
            SpotFleetRequestId="sfr-00000000-0000-0000-0000-000000000000", TargetCapacity=1
        )
    )
    assert err == "InvalidSpotFleetRequestId.NotFound", err
    expected_message = "The SpotFleetRequestId(s) sfr-00000000-0000-0000-0000-000000000000 do not exist."
    assert err_message == expected_message, f"expected message {expected_message!r}, got {err_message!r}"


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_and_subnet(ctx):
    # Prefer reusing an existing VPC/subnet (e.g. the run's shared network) to avoid
    # tripping the per-account VpcLimitExceeded quota; only create a fresh VPC/subnet
    # if nothing reusable is available.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        for subnet in subnets:
            if subnet.get("AvailableIpAddressCount", 0) > 0:
                return vpc["VpcId"], subnet["SubnetId"]

    name = ctx.unique_name("sim2real-behav-net-")
    vpc = ec2.create_vpc(CidrBlock="10.82.0.0/24", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.82.0.0/28", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


def _latest_amazon_linux_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
