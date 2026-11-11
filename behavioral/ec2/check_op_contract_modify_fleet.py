"""op-contract-modify-fleet."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-fleet"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyFleet updates a maintain-type fleet's excess-capacity policy and rejects unknown fleets."""
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ec2)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[_tag_spec("launch-template", lt_name)],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    # TotalTargetCapacity=0 keeps this free of any real instance launch while still
    # exercising the fleet lifecycle and ModifyFleet's contract.
    fleet_name = ctx.unique_name("sim2real-behav-fleet-")
    fleet = ec2.create_fleet(
        Type="maintain",
        LaunchTemplateConfigs=[
            {"LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"}}
        ],
        TargetCapacitySpecification={
            "TotalTargetCapacity": 0,
            "DefaultTargetCapacityType": "on-demand",
        },
        ExcessCapacityTerminationPolicy="termination",
        TagSpecifications=[_tag_spec("fleet", fleet_name)],
    )
    fleet_id = fleet["FleetId"]
    ctx.on_cleanup(lambda: ec2.delete_fleets(FleetIds=[fleet_id], TerminateInstances=True))

    resp = ec2.modify_fleet(FleetId=fleet_id, ExcessCapacityTerminationPolicy="no-termination")
    assert resp["Return"] is True, resp

    # DescribeFleets can lag ModifyFleet's write by a beat; poll for the updated policy
    # to propagate rather than asserting on the very first read.
    described = _poll_until(
        lambda: ec2.describe_fleets(FleetIds=[fleet_id])["Fleets"][0],
        lambda f: f["ExcessCapacityTerminationPolicy"] == "no-termination",
        timeout_s=60,
        interval_s=3,
    )
    assert described["ExcessCapacityTerminationPolicy"] == "no-termination", described

    # EC2 Fleet IDs are UUID-shaped ("fleet-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"), unlike the
    # flat 17-hex-char IDs used by most other EC2 resources. The all-zeros nil-style ID is
    # well-formed and never names a real fleet, so it reaches the not-found path. The call uses
    # the same single-parameter shape (ExcessCapacityTerminationPolicy alone) as above.
    bogus_fleet_id = "fleet-00000000-0000-0000-0000-000000000000"
    code, message = _client_error(
        lambda: ec2.modify_fleet(
            FleetId=bogus_fleet_id,
            ExcessCapacityTerminationPolicy="no-termination",
        )
    )
    assert code == "InvalidFleetId.NotFound", f"expected InvalidFleetId.NotFound, got {code}"
    expected_message = f"The FleetId(s) {bogus_fleet_id} do not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _tag_spec(resource_type, name):
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no amazon-owned al2023 AMIs found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
