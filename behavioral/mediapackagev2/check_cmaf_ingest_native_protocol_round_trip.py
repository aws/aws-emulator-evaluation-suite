"""cmaf-ingest-native-protocol-round-trip."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest

CHECK = "cmaf-ingest-native-protocol-round-trip"
GROUP = "native-protocol"
SERVICES = ["mediapackagev2"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The CMAF ingest URL from CreateChannel is a live HTTPS listener that answers an unauthenticated PUT
    with a 403 'Access denied' body and a PUT signed with the caller's SigV4 credentials with a different,
    signature-specific 403 body, never a 2xx."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    mp.create_channel_group(ChannelGroupName=group)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    created = mp.create_channel(ChannelGroupName=group, ChannelName=channel, InputType="HLS")
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))

    ingest_urls = [ep["Url"] for ep in created.get("IngestEndpoints", [])]
    assert ingest_urls, "CreateChannel did not return any IngestEndpoints"
    base_url = ingest_urls[0]
    assert base_url.startswith("https://"), f"ingest URL is not HTTPS: {base_url}"
    ingest_url = ctx.endpoint_url(base_url)

    body = b"not a valid CMAF fragment"

    # Negative class 1: no Authorization header at all.
    no_auth_status, no_auth_body = _http_put(ctx, ingest_url, body)
    assert not (200 <= no_auth_status < 300), (
        f"expected the live ingest endpoint to reject an unauthenticated PUT, "
        f"but got HTTP {no_auth_status}: {no_auth_body!r}"
    )
    assert no_auth_status == 403, (
        f"expected 403 for an unauthenticated push, got HTTP {no_auth_status}: {no_auth_body!r}"
    )
    assert b"access denied" in no_auth_body.lower(), (
        f"expected an 'Access denied' body for an unauthenticated push, got {no_auth_body!r}"
    )

    # Negative class 2: a syntactically-real but cryptographically wrong SigV4
    # Authorization header, signed with THIS account's own (control-plane-valid)
    # credentials. A faithful target must reject it for a DIFFERENT, specific reason
    # than class 1 -- proving it actually parses/verifies the header rather than
    # returning one hardcoded denial for every request.
    creds = mp._request_signer._credentials
    assert creds is not None, "no AWS credentials available to sign the ingest probe"
    frozen = creds.get_frozen_credentials()
    aws_req = AWSRequest(method="PUT", url=ingest_url, data=body)
    SigV4Auth(frozen, "mediapackagev2", ctx.region).add_auth(aws_req)
    signed_status, signed_body = _http_put(ctx, ingest_url, body, headers=dict(aws_req.headers))
    assert not (200 <= signed_status < 300), (
        f"expected the live ingest endpoint to reject a wrongly-signed PUT, "
        f"but got HTTP {signed_status}: {signed_body!r}"
    )
    assert signed_status == 403, (
        f"expected 403 for a wrongly-signed push, got HTTP {signed_status}: {signed_body!r}"
    )
    assert b"signature" in signed_body.lower(), (
        f"expected a signature-verification-specific denial for a wrongly-signed push, "
        f"got {signed_body!r}"
    )
    assert signed_body != no_auth_body, (
        "the ingest endpoint returned the IDENTICAL denial body whether or not an "
        f"Authorization header was present ({signed_body!r}) -- it is not distinguishing "
        "request classes at all, which is indistinguishable from a stub that denies every PUT"
    )


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _http_put(ctx, url: str, body: bytes, headers: dict | None = None) -> tuple[int, bytes]:
    """PUT body to url and return (status_code, response_body). Raises AssertionError
    if the endpoint is not reachable at all (DNS failure, connection refused, TLS
    failure) -- that is a hard fail, never a skip, since the endpoint was just
    provisioned by CreateChannel and must be live."""
    req = urllib.request.Request(url, data=body, method="PUT", headers=headers or {})
    tls_context = _ssl_context(ctx)
    try:
        with urllib.request.urlopen(req, timeout=15, context=tls_context) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        raise AssertionError(f"ingest endpoint {url} was not reachable: {e}") from e


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
