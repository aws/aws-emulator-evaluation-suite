"""engine-versions-and-dpu-sizes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "engine-versions-and-dpu-sizes"
GROUP = 'metadata'
SERVICES = ['athena']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEngineVersions must advertise at least one selectable engine, and ListApplicationDPUSizes
    must return well-formed, positive DPU sizes per runtime -- both server-managed and stable
    (identical) across repeated calls, independent of anything this check controls."""
    athena = ctx.client("athena")

    versions_1 = athena.list_engine_versions()["EngineVersions"]
    assert versions_1, "ListEngineVersions must return at least one engine version"
    for ev in versions_1:
        assert "SelectedEngineVersion" in ev or "EffectiveEngineVersion" in ev, (
            f"engine version entry missing both Selected/Effective fields: {ev}"
        )
    selected_1 = {ev.get("SelectedEngineVersion") for ev in versions_1 if ev.get("SelectedEngineVersion")}
    assert selected_1, "at least one engine version must expose SelectedEngineVersion"

    versions_2 = athena.list_engine_versions()["EngineVersions"]
    selected_2 = {ev.get("SelectedEngineVersion") for ev in versions_2 if ev.get("SelectedEngineVersion")}
    assert selected_2 == selected_1, (
        f"ListEngineVersions is not stable across calls: {selected_1} != {selected_2}"
    )

    dpu_1 = athena.list_application_dpu_sizes()
    assert "ApplicationDPUSizes" in dpu_1, "ListApplicationDPUSizes must return an ApplicationDPUSizes list"
    sizes_1 = dpu_1["ApplicationDPUSizes"]
    assert isinstance(sizes_1, list) and sizes_1, "ApplicationDPUSizes must be a non-empty list"
    by_runtime_1 = {}
    for entry in sizes_1:
        runtime_id = entry["ApplicationRuntimeId"]
        supported = entry["SupportedDPUSizes"]
        assert supported, f"{runtime_id} advertises no supported DPU sizes"
        assert all(isinstance(n, int) and n > 0 for n in supported), (
            f"{runtime_id} SupportedDPUSizes must be positive integers: {supported}"
        )
        by_runtime_1[runtime_id] = tuple(sorted(supported))

    dpu_2 = athena.list_application_dpu_sizes()["ApplicationDPUSizes"]
    by_runtime_2 = {
        entry["ApplicationRuntimeId"]: tuple(sorted(entry["SupportedDPUSizes"])) for entry in dpu_2
    }
    assert by_runtime_2 == by_runtime_1, (
        f"ListApplicationDPUSizes is not stable across calls: {by_runtime_1} != {by_runtime_2}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
