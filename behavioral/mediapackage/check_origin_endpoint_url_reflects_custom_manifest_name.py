"""origin-endpoint-url-reflects-custom-manifest-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "origin-endpoint-url-reflects-custom-manifest-name"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginEndpoint with a custom ManifestName produces a Url whose filename
    reflects that ManifestName rather than the "index" default, and DescribeOriginEndpoint
    returns the same Url/ManifestName pair afterward."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-oe-")
    manifest_name = "sim2real-custom-manifest"
    created = mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        HlsPackage={},
        ManifestName=manifest_name,
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    assert created["ManifestName"] == manifest_name, (
        f"expected ManifestName {manifest_name!r}, got {created.get('ManifestName')!r}"
    )
    assert manifest_name in created["Url"], (
        f"expected {manifest_name!r} in Url, got {created['Url']!r}"
    )
    filename = created["Url"].rsplit("/", 1)[-1]
    assert "index" not in filename, (
        f"expected custom ManifestName to replace the 'index' default in the Url filename, "
        f"got {filename!r}"
    )

    described = mp.describe_origin_endpoint(Id=endpoint_id)
    assert described["ManifestName"] == manifest_name, (
        f"expected DescribeOriginEndpoint ManifestName {manifest_name!r}, "
        f"got {described.get('ManifestName')!r}"
    )
    assert described["Url"] == created["Url"], (
        f"expected DescribeOriginEndpoint Url to match CreateOriginEndpoint's "
        f"{created['Url']!r}, got {described['Url']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
