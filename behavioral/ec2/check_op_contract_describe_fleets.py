"""op-contract-describeFleets."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeFleets"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFleets reflects a real fleet's configuration and rejects a bogus fleet ID."""
    ec2 = ctx.client("ec2")
    fleet_id, lt_id = _create_zero_capacity_fleet(ctx)

    # --- success path: the fleet we just created shows up with the configuration we asked for ---
    resp = _poll_until(
        lambda: ec2.describe_fleets(FleetIds=[fleet_id]),
        lambda r: len(r.get("Fleets", [])) == 1,
        timeout_s=30,
        interval_s=2,
    )
    fleets = resp["Fleets"]
    assert len(fleets) == 1, f"expected exactly 1 fleet for FleetIds=[{fleet_id}], got {len(fleets)}"
    fleet = fleets[0]
    assert fleet["FleetId"] == fleet_id, f"expected FleetId {fleet_id!r}, got {fleet['FleetId']!r}"
    assert fleet["Type"] == "maintain", f"expected Type 'maintain', got {fleet['Type']!r}"
    actual_capacity = fleet["TargetCapacitySpecification"]["TotalTargetCapacity"]
    assert actual_capacity == 0, f"expected TotalTargetCapacity 0, got {actual_capacity!r}"
    actual_lt_id = fleet["LaunchTemplateConfigs"][0]["LaunchTemplateSpecification"]["LaunchTemplateId"]
    assert actual_lt_id == lt_id, f"expected LaunchTemplateId {lt_id!r}, got {actual_lt_id!r}"

    # A describe call with no ID filter must also surface it.
    all_fleets = ec2.describe_fleets()["Fleets"]
    assert any(f["FleetId"] == fleet_id for f in all_fleets), (
        f"expected {fleet_id} in unfiltered DescribeFleets, got {[f['FleetId'] for f in all_fleets]!r}"
    )

    # --- error boundary: a well-formed but nonexistent fleet ID must be rejected specifically,
    # not silently dropped from the result set ---
    def _call():
        ec2.describe_fleets(FleetIds=["fleet-00000000-0000-0000-0000-000000000000"])

    code, message = _error_of(_call)
    assert code == "InvalidFleetId.NotFound", f"expected InvalidFleetId.NotFound, got {code!r}"
    assert message == "The FleetId(s) fleet-00000000-0000-0000-0000-000000000000 do not exist.", message


def _error_of(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")


def _latest_amazon_linux_ami(ec2):
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:
        resp = ec2.describe_images(
            Owners=["amazon"],
            Filters=[{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}],
        )
        images = sorted(resp["Images"], key=lambda i: i["CreationDate"], reverse=True)
    if not images:
        raise AssertionError("no Amazon Linux AMI available to build a launch template")
    return images[0]["ImageId"]


def _create_zero_capacity_fleet(ctx):
    """Create a real, zero-cost EC2 Fleet (TotalTargetCapacity=0 launches nothing)."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_amazon_linux_ami(ec2)
    lt_name = ctx.unique_name("sim2real-fleet-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": lt_name}]}],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    fleet = ec2.create_fleet(
        Type="maintain",
        LaunchTemplateConfigs=[
            {"LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"}}
        ],
        TargetCapacitySpecification={"TotalTargetCapacity": 0, "DefaultTargetCapacityType": "on-demand"},
        TagSpecifications=[{"ResourceType": "fleet", "Tags": [{"Key": "Name", "Value": lt_name}]}],
    )
    fleet_id = fleet["FleetId"]
    ctx.on_cleanup(lambda: ec2.delete_fleets(FleetIds=[fleet_id], TerminateInstances=False))
    return fleet_id, lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
