"""op-contract-describeFleetInstances."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeFleetInstances"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeFleetInstances reflects a real fleet's (empty) capacity and rejects a bogus fleet ID."""
    ec2 = ctx.client("ec2")
    fleet_id, _lt_id = _create_zero_capacity_fleet(ctx)

    # --- success path: a fleet requesting zero target capacity has zero active instances,
    # but the call must succeed and correctly scope the response to our fleet ---
    resp = _poll_until(
        lambda: ec2.describe_fleet_instances(FleetId=fleet_id),
        lambda r: r.get("FleetId") == fleet_id,
        timeout_s=30,
        interval_s=2,
    )
    assert resp["FleetId"] == fleet_id, f"expected FleetId {fleet_id!r}, got {resp.get('FleetId')!r}"
    assert resp["ActiveInstances"] == [], (
        f"expected no active instances for a zero-capacity fleet, got {resp['ActiveInstances']!r}"
    )

    # --- error boundary: a well-formed but nonexistent fleet ID must be rejected specifically ---
    bogus_fleet_id = "fleet-00000000-0000-0000-0000-000000000000"

    def _call():
        ec2.describe_fleet_instances(FleetId=bogus_fleet_id)

    code, message = _error(_call)
    assert code == "InvalidFleetId.NotFound", f"expected InvalidFleetId.NotFound, got {code!r}"
    expected = f"The FleetId(s) {bogus_fleet_id} do not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Return fn()'s (code, message); a success raises, never reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for predicate; last observed {last!r}")


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


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


def _create_zero_capacity_fleet(ctx):
    """Create a real, zero-cost EC2 Fleet (TotalTargetCapacity=0 launches nothing)."""
    ec2 = ctx.client("ec2")
    ami_id = _latest_amazon_linux_ami(ec2)
    lt = ec2.create_launch_template(
        LaunchTemplateName=ctx.unique_name("sim2real-fleet-lt-"),
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[_tag_spec(ctx, "launch-template")],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    fleet = ec2.create_fleet(
        Type="maintain",
        LaunchTemplateConfigs=[
            {"LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"}}
        ],
        TargetCapacitySpecification={"TotalTargetCapacity": 0, "DefaultTargetCapacityType": "on-demand"},
        TagSpecifications=[_tag_spec(ctx, "fleet")],
    )
    fleet_id = fleet["FleetId"]
    ctx.on_cleanup(lambda: ec2.delete_fleets(FleetIds=[fleet_id], TerminateInstances=False))
    return fleet_id, lt_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
