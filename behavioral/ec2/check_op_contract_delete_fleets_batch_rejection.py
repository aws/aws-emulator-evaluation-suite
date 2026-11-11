"""op-contract-delete-fleets-batch-rejection."""
from __future__ import annotations
from botocore.exceptions import ClientError

CHECK = "op-contract-delete-fleets-batch-rejection"
GROUP = "error-semantics"
SERVICES = ["ec2"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteFleets with a real fleet and an unknown fleet ID deletes the real one and reports the unknown
    one per item with fleetIdDoesNotExist and its exact message instead of raising; the real fleet
    then describes in a deleted state."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-fleet-")

    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, "no Amazon-owned al2023 x86_64 AMIs found to build a launch template from"
    images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
    image_id = images[0]["ImageId"]

    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": image_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id)))

    fleet = ec2.create_fleet(
        LaunchTemplateConfigs=[{"LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"}}],
        TargetCapacitySpecification={"TotalTargetCapacity": 0, "DefaultTargetCapacityType": "on-demand"},
        Type="maintain",
        TagSpecifications=[{"ResourceType": "fleet", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    fleet_id = fleet["FleetId"]
    ctx.on_cleanup(lambda: _ignore(lambda: ec2.delete_fleets(FleetIds=[fleet_id], TerminateInstances=True)))

    bogus_id = "fleet-00000000-0000-0000-0000-000000000000"
    resp = ec2.delete_fleets(FleetIds=[fleet_id, bogus_id], TerminateInstances=True)

    successful = {item["FleetId"] for item in resp["SuccessfulFleetDeletions"]}
    unsuccessful = {item["FleetId"]: item["Error"]["Code"] for item in resp["UnsuccessfulFleetDeletions"]}
    unsuccessful_messages = {item["FleetId"]: item["Error"].get("Message") for item in resp["UnsuccessfulFleetDeletions"]}

    assert fleet_id in successful, resp
    assert bogus_id in unsuccessful, resp
    assert unsuccessful[bogus_id] == "fleetIdDoesNotExist", (
        f"expected fleetIdDoesNotExist for the unknown fleet, got {unsuccessful[bogus_id]!r}: {resp}"
    )
    assert unsuccessful_messages[bogus_id] == "Fleet deletion failed. Fleet ID not found.", unsuccessful_messages[bogus_id]

    remaining = ec2.describe_fleets(FleetIds=[fleet_id])["Fleets"]
    assert remaining and remaining[0]["FleetState"] in ("deleted_terminating", "deleted_running", "deleted"), remaining


def _ignore(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidLaunchTemplateId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
