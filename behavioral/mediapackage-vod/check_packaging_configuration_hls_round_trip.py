"""packaging-configuration-hls-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "packaging-configuration-hls-round-trip"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePackagingConfiguration with a nested HlsPackage persists every field exactly as sent."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    config_id = ctx.unique_name("sim2real-mpvod-hlscfg-")
    hls_package = {
        "HlsManifests": [
            {
                "ManifestName": "index",
                "AdMarkers": "PASSTHROUGH",
                "IncludeIframeOnlyStream": True,
                "ProgramDateTimeIntervalSeconds": 60,
                "RepeatExtXKey": True,
            }
        ],
        "SegmentDurationSeconds": 6,
        "UseAudioRenditionGroup": True,
        "IncludeDvbSubtitles": False,
    }
    created = mpv.create_packaging_configuration(
        Id=config_id,
        PackagingGroupId=group_id,
        HlsPackage=hls_package,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_configuration(Id=config_id))

    assert created["Id"] == config_id, f"expected Id={config_id!r}, got {created['Id']!r}"
    assert created["PackagingGroupId"] == group_id, (
        f"expected PackagingGroupId={group_id!r}, got {created['PackagingGroupId']!r}"
    )
    assert "DashPackage" not in created or created.get("DashPackage") is None, (
        f"expected no DashPackage on an Hls-only config, got {created.get('DashPackage')!r}"
    )
    assert "MssPackage" not in created or created.get("MssPackage") is None, (
        f"expected no MssPackage on an Hls-only config, got {created.get('MssPackage')!r}"
    )
    assert "CmafPackage" not in created or created.get("CmafPackage") is None, (
        f"expected no CmafPackage on an Hls-only config, got {created.get('CmafPackage')!r}"
    )

    described = mpv.describe_packaging_configuration(Id=config_id)
    hls = described["HlsPackage"]
    assert hls["SegmentDurationSeconds"] == 6, (
        f"expected SegmentDurationSeconds=6, got {hls['SegmentDurationSeconds']!r}"
    )
    assert hls["UseAudioRenditionGroup"] is True, (
        f"expected UseAudioRenditionGroup=True, got {hls['UseAudioRenditionGroup']!r}"
    )
    assert hls["IncludeDvbSubtitles"] is False, (
        f"expected IncludeDvbSubtitles=False, got {hls['IncludeDvbSubtitles']!r}"
    )
    manifest = hls["HlsManifests"][0]
    assert manifest["ManifestName"] == "index", f"expected ManifestName=index, got {manifest['ManifestName']!r}"
    assert manifest["AdMarkers"] == "PASSTHROUGH", (
        f"expected AdMarkers=PASSTHROUGH, got {manifest['AdMarkers']!r}"
    )
    assert manifest["IncludeIframeOnlyStream"] is True, (
        f"expected IncludeIframeOnlyStream=True, got {manifest['IncludeIframeOnlyStream']!r}"
    )
    assert manifest["ProgramDateTimeIntervalSeconds"] == 60, (
        f"expected ProgramDateTimeIntervalSeconds=60, got {manifest['ProgramDateTimeIntervalSeconds']!r}"
    )
    assert manifest["RepeatExtXKey"] is True, (
        f"expected RepeatExtXKey=True, got {manifest['RepeatExtXKey']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
