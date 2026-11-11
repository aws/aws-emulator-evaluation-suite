"""hls-package-ad-markers-config-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "hls-package-ad-markers-config-persists"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-default HlsPackage configuration (AdMarkers/PlaylistType/PlaylistWindowSeconds)
    passed to CreateOriginEndpoint is persisted exactly, and survives an UpdateOriginEndpoint
    that changes only the Description."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-oe-")
    hls_package = {
        "AdMarkers": "SCTE35_ENHANCED",
        "PlaylistType": "EVENT",
        "PlaylistWindowSeconds": 120,
        "SegmentDurationSeconds": 6,
    }
    created = mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        Tags={"sim2real": "true"},
        HlsPackage=hls_package,
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    got = created["HlsPackage"]
    assert got["AdMarkers"] == "SCTE35_ENHANCED", f"expected AdMarkers=SCTE35_ENHANCED, got {got.get('AdMarkers')!r}"
    assert got["PlaylistType"] == "EVENT", f"expected PlaylistType=EVENT, got {got.get('PlaylistType')!r}"
    assert got["PlaylistWindowSeconds"] == 120, f"expected PlaylistWindowSeconds=120, got {got.get('PlaylistWindowSeconds')!r}"
    assert got["SegmentDurationSeconds"] == 6, f"expected SegmentDurationSeconds=6, got {got.get('SegmentDurationSeconds')!r}"

    # UpdateOriginEndpoint is a PUT: re-send the same packaging config alongside the
    # unrelated field change, and confirm it round-trips unchanged.
    updated = mp.update_origin_endpoint(
        Id=endpoint_id, Description="updated", HlsPackage=hls_package
    )
    assert updated["Description"] == "updated", f"expected Description=updated, got {updated.get('Description')!r}"
    got2 = updated["HlsPackage"]
    assert got2["AdMarkers"] == "SCTE35_ENHANCED", f"expected AdMarkers=SCTE35_ENHANCED after update, got {got2.get('AdMarkers')!r}"
    assert got2["PlaylistType"] == "EVENT", f"expected PlaylistType=EVENT after update, got {got2.get('PlaylistType')!r}"
    assert got2["PlaylistWindowSeconds"] == 120, f"expected PlaylistWindowSeconds=120 after update, got {got2.get('PlaylistWindowSeconds')!r}"
    assert got2["SegmentDurationSeconds"] == 6, f"expected SegmentDurationSeconds=6 after update, got {got2.get('SegmentDurationSeconds')!r}"

    described = mp.describe_origin_endpoint(Id=endpoint_id)
    got3 = described["HlsPackage"]
    assert got3["AdMarkers"] == "SCTE35_ENHANCED", f"independent read: expected AdMarkers=SCTE35_ENHANCED, got {got3.get('AdMarkers')!r}"
    assert got3["PlaylistType"] == "EVENT", f"independent read: expected PlaylistType=EVENT, got {got3.get('PlaylistType')!r}"
    assert got3["PlaylistWindowSeconds"] == 120, f"independent read: expected PlaylistWindowSeconds=120, got {got3.get('PlaylistWindowSeconds')!r}"
    assert got3["SegmentDurationSeconds"] == 6, f"independent read: expected SegmentDurationSeconds=6, got {got3.get('SegmentDurationSeconds')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
