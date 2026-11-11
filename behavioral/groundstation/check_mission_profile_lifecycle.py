"""mission-profile-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mission-profile-lifecycle"
GROUP = "state"
SERVICES = ["groundstation"]


def _error(fn):
    """Return the (code, message) of the ClientError ``fn`` raises; a success is a defect."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _tolerate_not_found(fn):
    """Run a cleanup delete; the check may already have deleted the resource."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A MissionProfile's fields round-trip through create/update/get, and after delete the
    profile is truly gone (ResourceNotFoundException), not merely hidden."""
    gs = ctx.client("groundstation")
    tracking_config = gs.create_config(
        name=ctx.unique_name("sim2real-gs-mp-track-"),
        configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        tags={"sim2real": "mission-profile-lifecycle"},
    )
    tracking_arn = tracking_config["configArn"]
    ctx.on_cleanup(
        lambda: gs.delete_config(
            configId=tracking_config["configId"], configType=tracking_config["configType"]
        )
    )

    name = ctx.unique_name("sim2real-gs-mp-")
    downlink = gs.create_config(
        name=ctx.unique_name("sim2real-gs-mp-downlink-"),
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7900.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                }
            }
        },
        tags={"sim2real": "mission-profile-lifecycle"},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=downlink["configId"], configType=downlink["configType"])
    )
    endpoint_cfg = gs.create_config(
        name=ctx.unique_name("sim2real-gs-mp-endpoint-"),
        configData={"dataflowEndpointConfig": {"dataflowEndpointName": "sim2real-endpoint"}},
        tags={"sim2real": "mission-profile-lifecycle"},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(
            configId=endpoint_cfg["configId"], configType=endpoint_cfg["configType"]
        )
    )

    created = gs.create_mission_profile(
        name=name,
        minimumViableContactDurationSeconds=30,
        contactPrePassDurationSeconds=60,
        contactPostPassDurationSeconds=90,
        dataflowEdges=[[downlink["configArn"], endpoint_cfg["configArn"]]],
        trackingConfigArn=tracking_arn,
        tags={"sim2real": "mission-profile-lifecycle"},
    )
    profile_id = created["missionProfileId"]
    ctx.on_cleanup(lambda: _tolerate_not_found(
        lambda: gs.delete_mission_profile(missionProfileId=profile_id)))

    fetched = gs.get_mission_profile(missionProfileId=profile_id)
    assert fetched["name"] == name, f"expected name {name!r}, got {fetched['name']!r}"
    assert fetched["minimumViableContactDurationSeconds"] == 30, (
        f"expected minimumViableContactDurationSeconds 30, got "
        f"{fetched['minimumViableContactDurationSeconds']!r}"
    )
    assert fetched["contactPrePassDurationSeconds"] == 60, (
        f"expected contactPrePassDurationSeconds 60, got {fetched['contactPrePassDurationSeconds']!r}"
    )
    assert fetched["trackingConfigArn"] == tracking_arn, (
        f"expected trackingConfigArn {tracking_arn!r}, got {fetched['trackingConfigArn']!r}"
    )

    new_name = name + "-updated"
    gs.update_mission_profile(
        missionProfileId=profile_id,
        name=new_name,
        contactPrePassDurationSeconds=120,
    )
    updated = gs.get_mission_profile(missionProfileId=profile_id)
    assert updated["name"] == new_name, f"expected updated name {new_name!r}, got {updated['name']!r}"
    assert updated["contactPrePassDurationSeconds"] == 120, (
        f"expected contactPrePassDurationSeconds 120 after update, got "
        f"{updated['contactPrePassDurationSeconds']!r}"
    )
    # Untouched field must survive the partial update.
    assert updated["minimumViableContactDurationSeconds"] == 30, (
        f"expected untouched minimumViableContactDurationSeconds to survive the partial update as "
        f"30, got {updated['minimumViableContactDurationSeconds']!r}"
    )

    gs.delete_mission_profile(missionProfileId=profile_id)
    refused = _error(lambda: gs.get_mission_profile(missionProfileId=profile_id))
    assert refused == ("ResourceNotFoundException", "MissionProfile not found"), (
        f"expected GetMissionProfile on a deleted profile to raise ResourceNotFoundException, got "
        f"{refused!r}"
    )

    # The dead id must also reject a mutation, not just a read.
    account = tracking_arn.split(":")[4]
    mutate_refused = _error(
        lambda: gs.update_mission_profile(missionProfileId=profile_id, name=new_name + "-again")
    )
    assert mutate_refused == (
        "ResourceNotFoundException",
        f"No mission profile found with ID {profile_id} for customer {account}",
    ), (
        f"expected UpdateMissionProfile on a deleted profile to raise ResourceNotFoundException, got "
        f"{mutate_refused!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
