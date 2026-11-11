"""op-contract-describe-spot-fleet-request-history."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-spot-fleet-request-history"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeSpotFleetRequestHistory for a submitted Spot Fleet returns its fleetRequestChange history;
    an unknown SpotFleetRequestId fails with InvalidSpotFleetRequestId.NotFound and DryRun answers
    DryRunOperation, each with its exact message."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    subnet_id = _create_subnet(ctx, ec2, "10.73.0.0/16", "sim2real-behav-spotfleet-net-")
    image_id = _latest_amazon_linux_ami(ec2)
    role_arn = _create_spot_fleet_role(ctx, iam)

    # This StartTime must have whole-second precision (fractional seconds fail with InvalidParameter)
    # and lie strictly in the past; 5 minutes of margin absorbs clock skew.
    start_time = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(microsecond=0)
    spot_fleet_request_id = _request_spot_fleet_with_retry(ctx, ec2, role_arn, image_id, subnet_id)

    def _cleanup_fleet():
        ec2.cancel_spot_fleet_requests(
            SpotFleetRequestIds=[spot_fleet_request_id], TerminateInstances=True
        )

    ctx.on_cleanup(_cleanup_fleet)

    # Success path: a freshly submitted fleet has a real history record of its own submission
    # -- an independent read at the destination, not the request_spot_fleet response itself.
    history = _poll_until(
        lambda: ec2.describe_spot_fleet_request_history(
            SpotFleetRequestId=spot_fleet_request_id, StartTime=start_time
        ),
        lambda resp: bool(resp["HistoryRecords"]),
        timeout_s=60,
        interval_s=5,
    )
    assert history["SpotFleetRequestId"] == spot_fleet_request_id, (
        f"expected the history to echo {spot_fleet_request_id!r}, got "
        f"{history['SpotFleetRequestId']!r}"
    )
    event_types = {r["EventType"] for r in history["HistoryRecords"]}
    assert "fleetRequestChange" in event_types, (
        f"expected a fleetRequestChange history event for a freshly submitted fleet, "
        f"got {event_types!r}"
    )

    # Error boundary: a syntactically valid but nonexistent SpotFleetRequestId.
    fake_id = "sfr-00000000-0000-0000-0000-000000000000"
    code, code_message = _error_code(
        lambda: ec2.describe_spot_fleet_request_history(
            SpotFleetRequestId=fake_id, StartTime=start_time
        )
    )
    assert code == "InvalidSpotFleetRequestId.NotFound", (
        f"expected InvalidSpotFleetRequestId.NotFound, got {code!r}"
    )
    expected_code_message = f"The SpotFleetRequestId(s) {fake_id} do not exist."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # DryRun on the *real* fleet request: proves the call is well-formed and the caller has
    # permission, a boundary distinct from resource lookup above.
    code2, code2_message = _error_code(
        lambda: ec2.describe_spot_fleet_request_history(
            SpotFleetRequestId=spot_fleet_request_id, StartTime=start_time, DryRun=True
        )
    )
    assert code2 == "DryRunOperation", f"expected DryRunOperation, got {code2!r}"
    expected_code2_message = "Request would have succeeded, but DryRun flag is set."
    assert code2_message == expected_code2_message, f"expected message {expected_code2_message!r}, got {code2_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_subnet(ctx, ec2, cidr, name_prefix):
    """A scratch VPC plus one subnet, both registered for cleanup; returns the subnet id."""
    name = ctx.unique_name(name_prefix)
    vpc_id = ec2.create_vpc(
        CidrBlock=cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
    )
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=cidr.replace("/16", "/24"),
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"],
        lambda state: state == "available",
        timeout_s=60,
    )
    return subnet_id


def _latest_amazon_linux_ami(ec2):
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2 AMI found to build a Spot Fleet launch spec")
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _create_spot_fleet_role(ctx, iam):
    role_name = ctx.unique_name("sim2real-behav-spotfleet-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "spotfleet.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)
    return role_arn


def _request_spot_fleet_with_retry(ctx, ec2, role_arn, image_id, subnet_id, *, timeout_s=90.0, interval_s=5.0):
    """IAM role trust/attachment is eventually consistent; retry request_spot_fleet until
    the freshly created role has propagated enough for Spot Fleet to accept it."""
    config = {
        "IamFleetRole": role_arn,
        "TargetCapacity": 0,
        "Type": "maintain",
        "LaunchSpecifications": [
            {
                "ImageId": image_id,
                "InstanceType": "t3.micro",
                "SubnetId": subnet_id,
            }
        ],
        "TagSpecifications": [
            {
                "ResourceType": "spot-fleet-request",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-spotfleet-")}],
            }
        ],
    }
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ec2.request_spot_fleet(SpotFleetRequestConfig=config)["SpotFleetRequestId"]
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"request_spot_fleet never succeeded within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
