"""mission-profile-nonexistent-tracking-config-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mission-profile-nonexistent-tracking-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["groundstation"]


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMissionProfile rejects a trackingConfigArn that is well-formed but does not
    reference any real Config, while a profile pointing at a real Config succeeds."""
    gs = ctx.client("groundstation")

    real_tracking = gs.create_config(
        name=ctx.unique_name("sim2real-gs-realtrack-"),
        configData={"trackingConfig": {"autotrack": "REQUIRED"}},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(
            configId=real_tracking["configId"], configType=real_tracking["configType"]
        )
    )

    good_name = ctx.unique_name("sim2real-gs-goodmp-")
    downlink = gs.create_config(
        name=ctx.unique_name("sim2real-gs-badmp-downlink-"),
        configData={
            "antennaDownlinkConfig": {
                "spectrumConfig": {
                    "centerFrequency": {"value": 7900.0, "units": "MHz"},
                    "bandwidth": {"value": 1.0, "units": "MHz"},
                }
            }
        },
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=downlink["configId"], configType=downlink["configType"])
    )
    endpoint_cfg = gs.create_config(
        name=ctx.unique_name("sim2real-gs-badmp-endpoint-"),
        configData={"dataflowEndpointConfig": {"dataflowEndpointName": "sim2real-endpoint"}},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(
            configId=endpoint_cfg["configId"], configType=endpoint_cfg["configType"]
        )
    )
    edges = [[downlink["configArn"], endpoint_cfg["configArn"]]]

    good_profile = gs.create_mission_profile(
        name=good_name,
        minimumViableContactDurationSeconds=30,
        dataflowEdges=edges,
        trackingConfigArn=real_tracking["configArn"],
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: gs.delete_mission_profile(missionProfileId=good_profile["missionProfileId"])
    )

    fake_id = "00000000-0000-0000-0000-000000000000"
    fake_arn = real_tracking["configArn"][:-36] + fake_id
    account = real_tracking["configArn"].split(":")[4]
    bad_name = ctx.unique_name("sim2real-gs-badmp-")

    refused = _error(
        lambda: gs.create_mission_profile(
            name=bad_name,
            minimumViableContactDurationSeconds=30,
            dataflowEdges=edges,
            trackingConfigArn=fake_arn,
            tags={"sim2real": CHECK},
        )
    )
    assert refused == (
        "ResourceNotFoundException",
        f"No config found with ID {fake_id} and config type: tracking for customer {account}",
    ), (
        f"expected ResourceNotFoundException for a well-formed but nonexistent "
        f"trackingConfigArn, got {refused!r}"
    )

    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = gs.list_mission_profiles(**kwargs)
        for entry in page.get("missionProfileList", []):
            assert entry["name"] != bad_name, (
                f"rejected mission profile {bad_name!r} was nonetheless created and is "
                f"visible via ListMissionProfiles"
            )
        next_token = page.get("nextToken")
        if not next_token:
            break


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
