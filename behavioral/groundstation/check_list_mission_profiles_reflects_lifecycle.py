"""list-mission-profiles-reflects-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-mission-profiles-reflects-lifecycle"
GROUP = "state"
SERVICES = ["groundstation"]


def _list_all_profile_ids(gs) -> set:
    ids = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        page = gs.list_mission_profiles(**kwargs)
        for entry in page.get("missionProfileList", []):
            ids.add(entry["missionProfileId"])
        next_token = page.get("nextToken")
        if not next_token:
            break
    return ids


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListMissionProfiles includes a newly created profile and excludes it after deletion, while
    a control profile that is never deleted remains listed throughout."""
    gs = ctx.client("groundstation")
    tracking = gs.create_config(
        name=ctx.unique_name("sim2real-gs-lmp-track-"),
        configData={"trackingConfig": {"autotrack": "PREFERRED"}},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(configId=tracking["configId"], configType=tracking["configType"])
    )
    downlink = gs.create_config(
        name=ctx.unique_name("sim2real-gs-lmp-downlink-"),
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
        name=ctx.unique_name("sim2real-gs-lmp-endpoint-"),
        configData={"dataflowEndpointConfig": {"dataflowEndpointName": "sim2real-endpoint"}},
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(
        lambda: gs.delete_config(
            configId=endpoint_cfg["configId"], configType=endpoint_cfg["configType"]
        )
    )

    dataflow_edges = [[downlink["configArn"], endpoint_cfg["configArn"]]]

    # Control profile: never deleted, so it must remain listed across both reads below — this
    # is what rules out a target that empties ListMissionProfiles on any delete.
    keep = gs.create_mission_profile(
        name=ctx.unique_name("sim2real-gs-lmp-keep-"),
        minimumViableContactDurationSeconds=30,
        dataflowEdges=dataflow_edges,
        trackingConfigArn=tracking["configArn"],
        tags={"sim2real": CHECK},
    )
    keep_id = keep["missionProfileId"]
    ctx.on_cleanup(lambda: gs.delete_mission_profile(missionProfileId=keep_id))

    profile = gs.create_mission_profile(
        name=ctx.unique_name("sim2real-gs-lmp-"),
        minimumViableContactDurationSeconds=30,
        dataflowEdges=dataflow_edges,
        trackingConfigArn=tracking["configArn"],
        tags={"sim2real": CHECK},
    )
    profile_id = profile["missionProfileId"]

    ids_before = _list_all_profile_ids(gs)
    assert profile_id in ids_before, f"expected new profile {profile_id} in {ids_before}"
    assert keep_id in ids_before, f"expected control profile {keep_id} in {ids_before}"

    gs.delete_mission_profile(missionProfileId=profile_id)

    ids_after = _list_all_profile_ids(gs)
    assert profile_id not in ids_after, f"expected {profile_id} gone from {ids_after}"
    assert keep_id in ids_after, f"expected control profile {keep_id} to remain in {ids_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
