"""op-contract-describe-spot-fleet-requests."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-spot-fleet-requests"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSpotFleetRequests answers with a list, returns exactly a submitted fleet when filtered by
    its ID, and fails an unknown SpotFleetRequestId with InvalidSpotFleetRequestId.NotFound and its
    exact message."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")

    # Success path: SpotFleetRequestIds is optional -- listing all requires no resource.
    resp = ec2.describe_spot_fleet_requests()
    assert "SpotFleetRequestConfigs" in resp, f"missing SpotFleetRequestConfigs, got keys {list(resp)}"
    assert isinstance(resp["SpotFleetRequestConfigs"], list), (
        f"expected a list, got {type(resp['SpotFleetRequestConfigs'])}"
    )

    # Positive control: a real fleet request must resolve through the SAME
    # ID-filtered call the negative below exercises.
    role_arn = _create_spot_fleet_role(ctx, iam)
    fleet_id = _request_spot_fleet_with_retry(ec2, role_arn, ctx=ctx)
    ctx.on_cleanup(lambda: _safe_cancel(ec2, fleet_id))

    described = ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[fleet_id])["SpotFleetRequestConfigs"]
    assert len(described) == 1, f"expected exactly the requested fleet, got {described!r}"
    assert described[0]["SpotFleetRequestId"] == fleet_id, (
        f"expected {fleet_id!r}, got {described[0]['SpotFleetRequestId']!r}"
    )

    # Error boundary: syntactically valid but nonexistent ID.
    fake_id = "sfr-ffffffff-ffff-ffff-ffff-ffffffffffff"
    code, message = _client_error(lambda: ec2.describe_spot_fleet_requests(SpotFleetRequestIds=[fake_id]))
    assert code == "InvalidSpotFleetRequestId.NotFound", f"expected NotFound, got {code!r}"
    expected_message = f"The SpotFleetRequestId(s) {fake_id} do not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


_SPOT_FLEET_TAGGING_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AmazonEC2SpotFleetTaggingRole"


def _client_error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded with {result!r}")


def _create_spot_fleet_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-dsfr-role-")
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "spotfleet.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SPOT_FLEET_TAGGING_POLICY_ARN)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_SPOT_FLEET_TAGGING_POLICY_ARN)
    )
    return role_arn


def _latest_amazon_linux_ami(ec2) -> str:
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


def _default_subnet_id(ec2, *, ctx) -> str | None:
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    return subnets[0]["SubnetId"] if subnets else None


def _request_spot_fleet_with_retry(ec2, role_arn: str, *, timeout_s=90.0, interval_s=5.0, ctx) -> str:
    """IAM role trust/attachment is eventually consistent; retry request_spot_fleet until the
    freshly created role has propagated enough for Spot Fleet to accept it. TargetCapacity=0
    means the request exists (and is describable by ID) without ever launching an instance."""
    subnet_id = _default_subnet_id(ec2, ctx=ctx)
    if subnet_id is None:
        raise AssertionError("no network subnet available to build a Spot Fleet launch spec")
    config = {
        "IamFleetRole": role_arn,
        "TargetCapacity": 0,
        "Type": "maintain",
        "LaunchSpecifications": [
            {"ImageId": _latest_amazon_linux_ami(ec2), "InstanceType": "t3.micro", "SubnetId": subnet_id}
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


def _safe_cancel(ec2, fleet_id: str) -> None:
    ec2.cancel_spot_fleet_requests(SpotFleetRequestIds=[fleet_id], TerminateInstances=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
