"""packaging-configuration-mss-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "packaging-configuration-mss-round-trip"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePackagingConfiguration with a nested MssPackage persists every field exactly as sent."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(
        Id=group_id, Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mpvod-group-"}
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    config_id = ctx.unique_name("sim2real-mpvod-msscfg-")
    mss_package = {
        "MssManifests": [{"ManifestName": "smooth"}],
        "SegmentDurationSeconds": 3,
    }
    created = mpv.create_packaging_configuration(
        Id=config_id,
        PackagingGroupId=group_id,
        MssPackage=mss_package,
        Tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mpvod-msscfg-"},
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_configuration(Id=config_id))
    assert created["Id"] == config_id, f"expected Id={config_id!r}, got {created['Id']!r}"
    assert created["PackagingGroupId"] == group_id, (
        f"expected PackagingGroupId={group_id!r}, got {created['PackagingGroupId']!r}"
    )
    for other in ("DashPackage", "HlsPackage", "CmafPackage"):
        assert not created.get(other), (
            f"expected no {other} on an MSS-only config, got {created.get(other)!r}"
        )

    described = mpv.describe_packaging_configuration(Id=config_id)
    mss = described["MssPackage"]
    assert mss["SegmentDurationSeconds"] == 3, (
        f"expected SegmentDurationSeconds=3, got {mss['SegmentDurationSeconds']!r}"
    )
    assert mss["MssManifests"][0]["ManifestName"] == "smooth", (
        f"expected ManifestName='smooth', got {mss['MssManifests'][0]['ManifestName']!r}"
    )
    for other in ("DashPackage", "HlsPackage", "CmafPackage"):
        assert not described.get(other), (
            f"expected no {other} on describe of an MSS-only config, got {described.get(other)!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
