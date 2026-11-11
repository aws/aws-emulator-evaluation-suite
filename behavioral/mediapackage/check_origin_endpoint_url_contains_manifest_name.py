"""origin-endpoint-url-contains-manifest-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "origin-endpoint-url-contains-manifest-name"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The OriginEndpoint's system-generated Url incorporates the caller-supplied
    ManifestName, and DescribeOriginEndpoint returns the identical Url."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-url-")
    mp.create_channel(Id=cid)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    oid = ctx.unique_name("sim2real-mp-oe-")
    manifest_name = "myshowmanifest"
    created = mp.create_origin_endpoint(
        Id=oid, ChannelId=cid, ManifestName=manifest_name, HlsPackage={}
    )

    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=oid))

    expected_filename = f"{manifest_name}.m3u8"

    assert created["ManifestName"] == manifest_name, (
        f"expected ManifestName {manifest_name!r}, got {created['ManifestName']!r}"
    )
    created_filename = created["Url"].rsplit("/", 1)[-1]
    assert created_filename == expected_filename, (
        f"expected Url filename {expected_filename!r}, got {created_filename!r} "
        f"(full Url {created['Url']!r})"
    )

    described = mp.describe_origin_endpoint(Id=oid)
    assert described["Url"] == created["Url"], (
        f"DescribeOriginEndpoint Url {described['Url']!r} != CreateOriginEndpoint Url {created['Url']!r}"
    )
    described_filename = described["Url"].rsplit("/", 1)[-1]
    assert described_filename == expected_filename, (
        f"expected Url filename {expected_filename!r}, got {described_filename!r} "
        f"(full Url {described['Url']!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
