"""create-origin-endpoint-multiple-hls-manifests-url-uniqueness."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-origin-endpoint-multiple-hls-manifests-url-uniqueness"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An origin endpoint with two HLS manifest configs gets two distinct, per-manifest egress URLs."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "primary"}, {"ManifestName": "secondary"}],
        Tags={"purpose": "behavioral"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )

    manifests = created["HlsManifests"]
    assert len(manifests) == 2, f"expected 2 HlsManifests entries, got {len(manifests)}: {manifests}"
    names = {m["ManifestName"] for m in manifests}
    assert names == {"primary", "secondary"}, f"expected manifest names {{primary, secondary}}, got {names}"
    urls = {m["ManifestName"]: m["Url"] for m in manifests}
    assert urls["primary"] != urls["secondary"], (
        f"expected distinct per-manifest URLs, both manifests got {urls['primary']!r}"
    )
    assert "primary" in urls["primary"], f"expected manifest name 'primary' in its own URL, got {urls['primary']!r}"
    assert "secondary" in urls["secondary"], (
        f"expected manifest name 'secondary' in its own URL, got {urls['secondary']!r}"
    )

    fetched = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    fetched_urls = {m["ManifestName"]: m["Url"] for m in fetched["HlsManifests"]}
    assert fetched_urls == urls, f"GetOriginEndpoint URLs {fetched_urls} do not match CreateOriginEndpoint URLs {urls}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
