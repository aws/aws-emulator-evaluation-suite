"""op-contract-describeSpotFleetInstances."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSpotFleetInstances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSpotFleetInstances echoes the requesting SpotFleetRequestId and an
    ActiveInstanceSet consistent with a zero-target-capacity fleet (no instances ever
    launch), and rejects a well-formed but nonexistent Spot Fleet request ID."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if subnet_id is None:
        raise AssertionError("no network subnet available to build a Spot Fleet launch spec")
    image_id = _latest_amazon_linux_ami(ec2)
    role_arn = _create_spot_fleet_role(ctx, iam)

    spot_fleet_request_id = _request_spot_fleet_with_retry(ec2, role_arn, image_id, subnet_id)

    def _cleanup_fleet():
        ec2.cancel_spot_fleet_requests(
            SpotFleetRequestIds=[spot_fleet_request_id], TerminateInstances=True
        )

    ctx.on_cleanup(_cleanup_fleet)

    resp = ec2.describe_spot_fleet_instances(SpotFleetRequestId=spot_fleet_request_id)
    assert resp["SpotFleetRequestId"] == spot_fleet_request_id, (
        f"expected DescribeSpotFleetInstances to echo {spot_fleet_request_id!r}, "
        f"got {resp.get('SpotFleetRequestId')!r}"
    )
    assert resp["ActiveInstances"] == [], (
        f"a fleet request created with TargetCapacity=0 must never have active instances, "
        f"got {resp['ActiveInstances']!r}"
    )

    code, message = _client_error(
        lambda: ec2.describe_spot_fleet_instances(SpotFleetRequestId="sfr-00000000-0000-0000-0000-000000000000")
    )
    assert code == "InvalidSpotFleetRequestId.NotFound", f"expected InvalidSpotFleetRequestId.NotFound, got {code!r}"
    expected_message = "The SpotFleetRequestId(s) sfr-00000000-0000-0000-0000-000000000000 do not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(
        f"expected DescribeSpotFleetInstances to reject a nonexistent SpotFleetRequestId, "
        f"but it SUCCEEDED and returned {result!r}"
    )


def _default_subnet_id(ec2, *, ctx):
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    return subnets[0]["SubnetId"] if subnets else None


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _request_spot_fleet_with_retry(ec2, role_arn, image_id, subnet_id, *, timeout_s=90.0, interval_s=5.0):
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
            {"ResourceType": "spot-fleet-request", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
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
