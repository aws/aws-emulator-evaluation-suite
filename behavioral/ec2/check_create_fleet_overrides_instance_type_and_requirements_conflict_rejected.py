"""create-fleet-overrides-instance-type-and-requirements-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-fleet-overrides-instance-type-and-requirements-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_GONE_CODES = ("InvalidInstanceID.NotFound",)

_INSTANCE_TYPE = "t3.micro"
_REQUIREMENTS = {
    "VCpuCount": {"Min": 1, "Max": 2},
    "MemoryMiB": {"Min": 512, "Max": 2048},
}
_CONFLICT_ERR = (
    "InvalidParameterValue",
    "You can specify either InstanceRequirements or InstanceType, but not both. "
    "Remove either InstanceRequirements or InstanceType, and try again.",
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFleet refuses an Overrides entry carrying both InstanceType and
    InstanceRequirements with its exact code and message and creates no fleet, while an
    Overrides entry naming InstanceType alone launches the requested instance."""
    ec2 = ctx.client("ec2")
    net = ctx.network()

    ami_id = _latest_al2023_ami(ec2)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": _INSTANCE_TYPE},
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    offered = {
        o["Location"] for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}],
        )["InstanceTypeOfferings"]
    }
    usable = [az for az in net.availability_zones if az in offered]
    assert usable, f"no zone of the run's network offers {_INSTANCE_TYPE!r}: {net.availability_zones!r}"
    subnet_id = net.subnets[usable[0]]

    # Positive control: an Overrides entry naming InstanceType alone is accepted and launches
    # exactly one instance of that type.
    good_name = ctx.unique_name("sim2real-behav-fleet-")
    good = ec2.create_fleet(
        LaunchTemplateConfigs=[{
            "LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"},
            "Overrides": [{"InstanceType": _INSTANCE_TYPE, "SubnetId": subnet_id}],
        }],
        TargetCapacitySpecification={"TotalTargetCapacity": 1, "DefaultTargetCapacityType": "on-demand"},
        Type="instant",
        TagSpecifications=[{"ResourceType": "fleet", "Tags": [{"Key": "Name", "Value": good_name}]}],
    )
    ctx.on_cleanup(lambda: _delete_instant_fleet(ec2, good))
    instance_ids = [i for group in good.get("Instances", []) for i in group["InstanceIds"]]
    assert len(instance_ids) == 1, f"expected exactly one launched instance, got {good['Instances']!r}"
    instance_id = instance_ids[0]
    described = _poll(
        lambda: _describe(ec2, instance_id), lambda i: i is not None,
        timeout_s=180.0, interval_s=5.0, what=f"instance {instance_id} becoming visible to DescribeInstances",
    )
    assert described["InstanceType"] == _INSTANCE_TYPE, described

    # Negative: the same Overrides entry additionally naming InstanceRequirements is rejected,
    # and no fleet is created for it.
    bad_fleet_name = ctx.unique_name("sim2real-behav-fleet-")
    expect_error(
        lambda: ec2.create_fleet(
            LaunchTemplateConfigs=[{
                "LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"},
                "Overrides": [{
                    "InstanceType": _INSTANCE_TYPE,
                    "InstanceRequirements": _REQUIREMENTS,
                    "SubnetId": subnet_id,
                }],
            }],
            TargetCapacitySpecification={"TotalTargetCapacity": 1, "DefaultTargetCapacityType": "on-demand"},
            Type="instant",
            TagSpecifications=[{"ResourceType": "fleet", "Tags": [{"Key": "Name", "Value": bad_fleet_name}]}],
        ),
        *_CONFLICT_ERR,
        undo=lambda result: ctx.on_cleanup(
            lambda: ec2.delete_fleets(FleetIds=[result["FleetId"]], TerminateInstances=True)
        ),
    )
    leaked = _fleet_ids_named(ec2, bad_fleet_name)
    assert leaked == set(), f"CreateFleet was rejected but created fleet(s) anyway: {leaked}"


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _fleet_ids_named(ec2, name):
    ids = set()
    token = None
    while True:
        page = ec2.describe_fleets(**({"NextToken": token} if token else {}))
        ids.update(
            f["FleetId"] for f in page["Fleets"] if {"Key": "Name", "Value": name} in f.get("Tags", [])
        )
        token = page.get("NextToken")
        if not token:
            return ids


def _poll(probe, predicate, *, timeout_s, interval_s, what):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _describe(ec2, instance_id):
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _GONE_CODES:
            return None
        raise
    if not resv or not resv[0].get("Instances"):
        return None
    return resv[0]["Instances"][0]


def _state(ec2, instance_id):
    inst = _describe(ec2, instance_id)
    return "__gone__" if inst is None else inst["State"]["Name"]


def _delete_instant_fleet(ec2, created) -> None:
    """Delete the instant fleet with its instances, then wait for every instance it launched."""
    resp = ec2.delete_fleets(FleetIds=[created["FleetId"]], TerminateInstances=True)
    failed = [
        u for u in resp.get("UnsuccessfulFleetDeletions", [])
        if u["Error"]["Code"] != "fleetIdDoesNotExist"
    ]
    if failed:
        raise AssertionError(f"DeleteFleets failed for {created['FleetId']}: {failed!r}")
    for group in created.get("Instances", []):
        for instance_id in group["InstanceIds"]:
            _terminate(ec2, instance_id)


def _terminate(ec2, instance_id: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise
        return
    _poll(
        lambda: _state(ec2, instance_id), lambda s: s in ("terminated", "__gone__"),
        timeout_s=600.0, interval_s=5.0, what=f"instance {instance_id} reaching 'terminated'",
    )


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023.*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI visible in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
