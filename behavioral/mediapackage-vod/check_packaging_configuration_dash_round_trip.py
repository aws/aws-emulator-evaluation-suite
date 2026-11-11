"""packaging-configuration-dash-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "packaging-configuration-dash-round-trip"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePackagingConfiguration with a nested DashPackage persists every field exactly as sent."""
    mpv = ctx.client("mediapackage-vod")
    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    config_id = ctx.unique_name("sim2real-mpvod-dashcfg-")
    dash_package = {
        "DashManifests": [
            {
                "ManifestName": "dash",
                "ManifestLayout": "FULL",
                "MinBufferTimeSeconds": 5,
                "Profile": "NONE",
                "ScteMarkersSource": "SEGMENTS",
            }
        ],
        "SegmentDurationSeconds": 4,
        "PeriodTriggers": ["ADS"],
        "IncludeIframeOnlyStream": True,
        "IncludeEncoderConfigurationInSegments": True,
        "SegmentTemplateFormat": "NUMBER_WITH_TIMELINE",
    }
    created = mpv.create_packaging_configuration(
        Id=config_id,
        PackagingGroupId=group_id,
        DashPackage=dash_package,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: mpv.delete_packaging_configuration(Id=config_id))
    assert created["Id"] == config_id, f"expected Id={config_id!r}, got {created['Id']!r}"
    assert created["PackagingGroupId"] == group_id, (
        f"expected PackagingGroupId={group_id!r}, got {created['PackagingGroupId']!r}"
    )
    assert "HlsPackage" not in created or created.get("HlsPackage") is None, (
        f"expected no HlsPackage on a Dash-only config, got {created.get('HlsPackage')!r}"
    )
    assert "MssPackage" not in created or created.get("MssPackage") is None, (
        f"expected no MssPackage on a Dash-only config, got {created.get('MssPackage')!r}"
    )
    assert "CmafPackage" not in created or created.get("CmafPackage") is None, (
        f"expected no CmafPackage on a Dash-only config, got {created.get('CmafPackage')!r}"
    )

    described = mpv.describe_packaging_configuration(Id=config_id)
    dash = described["DashPackage"]
    assert dash["SegmentDurationSeconds"] == 4, (
        f"expected SegmentDurationSeconds=4, got {dash['SegmentDurationSeconds']!r}"
    )
    assert dash["PeriodTriggers"] == ["ADS"], f"expected PeriodTriggers=['ADS'], got {dash['PeriodTriggers']!r}"
    assert dash["IncludeIframeOnlyStream"] is True, (
        f"expected IncludeIframeOnlyStream=True, got {dash['IncludeIframeOnlyStream']!r}"
    )
    assert dash["IncludeEncoderConfigurationInSegments"] is True, (
        f"expected IncludeEncoderConfigurationInSegments=True, "
        f"got {dash['IncludeEncoderConfigurationInSegments']!r}"
    )
    assert dash["SegmentTemplateFormat"] == "NUMBER_WITH_TIMELINE", (
        f"expected SegmentTemplateFormat=NUMBER_WITH_TIMELINE, got {dash['SegmentTemplateFormat']!r}"
    )
    manifest = dash["DashManifests"][0]
    assert manifest["ManifestName"] == "dash", f"expected ManifestName=dash, got {manifest['ManifestName']!r}"
    assert manifest["ManifestLayout"] == "FULL", f"expected ManifestLayout=FULL, got {manifest['ManifestLayout']!r}"
    assert manifest["MinBufferTimeSeconds"] == 5, (
        f"expected MinBufferTimeSeconds=5, got {manifest['MinBufferTimeSeconds']!r}"
    )
    assert manifest["Profile"] == "NONE", f"expected Profile=NONE, got {manifest['Profile']!r}"
    assert manifest["ScteMarkersSource"] == "SEGMENTS", (
        f"expected ScteMarkersSource=SEGMENTS, got {manifest['ScteMarkersSource']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
