"""origin-endpoint-manifest-404-before-ingest."""
from __future__ import annotations

import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "origin-endpoint-manifest-404-before-ingest"
GROUP = "data-plane"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A GET of the manifest Url of a new HLS OriginEndpoint that has received no ingested content
    answers HTTP 404, not a 200 manifest."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-manifest-")
    mp.create_channel(Id=cid, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    oid = ctx.unique_name("sim2real-mp-oe-")
    endpoint = mp.create_origin_endpoint(
        Id=oid,
        ChannelId=cid,
        ManifestName="index",
        HlsPackage={"SegmentDurationSeconds": 6},
        Tags={"created-by": "sim2real"},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=oid))

    url = endpoint["Url"]
    try:
        target_url, route_headers = ctx.endpoint_route(url)
        with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=30) as resp:
            status = resp.status
    except urllib.error.HTTPError as e:
        status = e.code
    except urllib.error.URLError as e:
        raise AssertionError(f"origin endpoint manifest unreachable: {e}") from e

    assert status == 404, (
        f"expected 404 for an OriginEndpoint manifest with no ingested content, got {status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
