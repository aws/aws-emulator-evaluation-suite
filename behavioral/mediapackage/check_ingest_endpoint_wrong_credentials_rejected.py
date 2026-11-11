"""ingest-endpoint-wrong-credentials-rejected."""
from __future__ import annotations

import base64
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "ingest-endpoint-wrong-credentials-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _put_with_basic_auth(ctx, url: str, username: str, password: str, body: bytes) -> tuple[int, bytes]:
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=body, method="PUT", headers=route_headers)
    creds = base64.b64encode(f"{username}:{password}".encode()).decode()
    req.add_header("Authorization", f"Basic {creds}")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The HLS ingest URL of a healthy channel answers a Basic-auth PUT with the same 403 body for correct
    and wrong credentials (the push listener is closed, not credential-gated), and the channel's origin
    endpoint answers 404, so nothing was ingested."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-auth-")
    created = mp.create_channel(Id=cid, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    endpoint = created["HlsIngest"]["IngestEndpoints"][0]
    url = endpoint["Url"]
    username = endpoint["Username"]
    password = endpoint["Password"]

    # Positive control: the control plane and the generated credentials are
    # healthy, so a 403 below cannot be explained by a broken account/channel.
    assert username and password, (
        "CreateChannel did not provision usable ingest credentials"
    )
    assert not (p := ctx.published_url_mismatch(url)), p
    described = mp.describe_channel(Id=cid)
    assert described["Id"] == cid, f"DescribeChannel returned Id {described['Id']!r}, expected {cid!r}"
    assert described["HlsIngest"]["IngestEndpoints"][0]["Username"] == username, (
        "DescribeChannel did not echo back the same ingest credentials CreateChannel returned"
    )

    wrong_status, wrong_body = _put_with_basic_auth(ctx, url, username, password + "-wrong", b"sim2real-probe")
    assert wrong_status == 403, f"expected 403 for wrong ingest password, got {wrong_status}"

    correct_status, correct_body = _put_with_basic_auth(ctx, url, username, password, b"sim2real-probe")
    assert correct_status == 403 and correct_body == wrong_body, (
        f"expected correct credentials to draw the SAME blanket 403 as wrong credentials "
        f"(got status={correct_status} body={correct_body!r} vs wrong body={wrong_body!r}); "
        "if these ever diverge, real AWS has reopened credential-gated ingest and this check "
        "must go back to asserting that the correct call is NOT rejected"
    )

    # Independent read at the destination: an origin endpoint on the same channel
    # never serves any content, proving the ingest attempts above never landed
    # anything — the 403s are not a false negative masking a partial write.
    oe_id = cid + "-oe"
    oe = mp.create_origin_endpoint(ChannelId=cid, Id=oe_id, HlsPackage={}, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=oe_id))
    try:
        target_url, route_headers = ctx.endpoint_route(oe["Url"])
        with urllib.request.urlopen(urllib.request.Request(target_url, headers=route_headers), timeout=15) as resp:
            playback_status = resp.status
    except urllib.error.HTTPError as e:
        playback_status = e.code
    assert playback_status == 404, (
        f"expected no manifest at a channel that never accepted an ingest PUT, got {playback_status}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
