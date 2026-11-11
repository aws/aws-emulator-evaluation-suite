"""delete-config-referenced-by-mission-profile-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-config-referenced-by-mission-profile-rejected"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfig enforces referential integrity: it is rejected with InvalidParameterException
    while a MissionProfile still references the Config as its trackingConfigArn, and only
    succeeds once that MissionProfile has been deleted first."""
    gs = ctx.client("groundstation")
    config_name = ctx.unique_name("sim2real-gs-track-")
    config = gs.create_config(
        name=config_name,
        configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        tags={"sim2real": "dcref"},
    )
    config_id = config["configId"]
    config_type = config["configType"]
    config_arn = config["configArn"]
    ctx.on_cleanup(lambda: _tolerate_not_found(
        lambda: gs.delete_config(configId=config_id, configType=config_type)))

    downlink = gs.create_config(
        name=ctx.unique_name("sim2real-gs-dcref-downlink-"),
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7900.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                }
            }
        },
        tags={"sim2real": "dcref"},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=downlink["configId"], configType=downlink["configType"])
    )
    endpoint_cfg = gs.create_config(
        name=ctx.unique_name("sim2real-gs-dcref-endpoint-"),
        configData={"dataflowEndpointConfig": {"dataflowEndpointName": "sim2real-endpoint"}},
        tags={"sim2real": "dcref"},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(
            configId=endpoint_cfg["configId"], configType=endpoint_cfg["configType"]
        )
    )

    profile_name = ctx.unique_name("sim2real-gs-mp-")
    profile = gs.create_mission_profile(
        name=profile_name,
        minimumViableContactDurationSeconds=30,
        dataflowEdges=[[downlink["configArn"], endpoint_cfg["configArn"]]],
        trackingConfigArn=config_arn,
        tags={"sim2real": "dcref"},
    )
    profile_id = profile["missionProfileId"]
    ctx.on_cleanup(lambda: _tolerate_not_found(
        lambda: gs.delete_mission_profile(missionProfileId=profile_id)))

    # Deleting the still-referenced Config must be rejected -- referential integrity is enforced.
    profile_arn = config_arn.split(":config/")[0] + f":mission-profile/{profile_id}"
    refused = _error(lambda: gs.delete_config(configId=config_id, configType=config_type))
    assert refused == (
        "InvalidParameterException",
        "Config cannot be deleted; it is currently being used by the following Mission Profiles: "
        f"{profile_arn}",
    ), f"unexpected outcome deleting a referenced Config: {refused!r}"

    # The Config and mission profile both still exist, ARN intact.
    still_there = gs.get_config(configId=config_id, configType=config_type)
    assert still_there["configArn"] == config_arn, (
        f"expected the blocked-delete Config to still report its original ARN {config_arn!r}, "
        f"got {still_there['configArn']!r}"
    )
    fetched_profile = gs.get_mission_profile(missionProfileId=profile_id)
    assert fetched_profile["trackingConfigArn"] == config_arn, (
        f"expected the MissionProfile to still reference {config_arn!r}, "
        f"got {fetched_profile['trackingConfigArn']!r}"
    )

    # Once the referencing MissionProfile is deleted, the Config can be deleted too.
    gs.delete_mission_profile(missionProfileId=profile_id)
    gs.delete_config(configId=config_id, configType=config_type)
    refused = _error(lambda: gs.get_config(configId=config_id, configType=config_type))
    assert refused == (
        "ResourceNotFoundException",
        f"No config found with id {config_id} and type {config_type}",
    ), f"expected GetConfig on a deleted Config to raise ResourceNotFoundException, got {refused!r}"

    # The dead id is not just unreadable -- a further mutation on it fails too, rather than
    # silently no-op-ing or resurrecting the Config.
    refused = _error(lambda: gs.delete_config(configId=config_id, configType=config_type))
    assert refused == (
        "ResourceNotFoundException",
        f"Config {config_id} with type {config_type} not found",
    ), (
        f"expected a second DeleteConfig on an already-deleted id to also raise "
        f"ResourceNotFoundException, got {refused!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
