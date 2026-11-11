"""ingest-endpoint-webdav-basic-auth-scheme-refused."""
from __future__ import annotations

import base64
import urllib.error
import urllib.request

from behavioral_harness import tags

CHECK = "ingest-endpoint-webdav-basic-auth-scheme-refused"
GROUP = "data-plane"
SERVICES = ["mediapackage"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """MediaPackage's HLS ingest WebDAV endpoint refuses the AUTH SCHEME, not the credential: an
    unauthenticated PUT is challenged with 401 and `WWW-Authenticate: Digest realm="WebDAV"`, while
    an HTTP Basic PUT gets a bare 403 with no challenge, identically for correct and wrong passwords."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    created = mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint = created["HlsIngest"]["IngestEndpoints"][0]
    url = endpoint["Url"]
    username = endpoint["Username"]
    password = endpoint["Password"]

    wrong_status, wrong_challenge = _put(ctx, url, "wrong-user", "wrong-password", b"segment-data")
    assert wrong_status == 403, f"expected 403 for bad ingest basic-auth credentials, got {wrong_status}"
    assert wrong_challenge is None, (
        f"expected no WWW-Authenticate challenge on the Basic 403, got {wrong_challenge!r}"
    )

    correct_status, correct_challenge = _put(ctx, url, username, password, b"segment-data")
    assert correct_status == 403, (
        "expected the CORRECT system-generated credentials presented over HTTP Basic to draw the "
        f"same bare 403 as wrong ones -- the scheme is what is refused -- got {correct_status}"
    )
    assert correct_challenge is None, (
        f"expected no WWW-Authenticate challenge on the Basic 403, got {correct_challenge!r}"
    )

    # The discriminator: the listener is alive and genuinely credential-gated -- drop the
    # Authorization header entirely and it challenges for Digest rather than blanket-403ing.
    bare_status, bare_challenge = _put(ctx, url, None, None, b"segment-data")
    assert bare_status == 401, (
        f"expected an unauthenticated PUT to be challenged with 401, got {bare_status}; without "
        "this the 403s above would be indistinguishable from a listener that is simply closed"
    )
    assert bare_challenge is not None and "Digest" in bare_challenge and 'realm="WebDAV"' in bare_challenge, (
        f'expected a `Digest realm="WebDAV"` challenge on the unauthenticated PUT, got {bare_challenge!r}'
    )


# ===== helpers =====
def _put(ctx, url: str, username: str | None, password: str | None, body: bytes) -> tuple[int, str | None]:
    """PUT to the ingest URL; return (status, WWW-Authenticate). No Authorization header at all
    when *username* is None -- that arm is the scheme discriminator."""
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=body, method="PUT", headers=route_headers)
    if username is not None:
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    req.add_header("Content-Type", "application/octet-stream")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.headers.get("WWW-Authenticate")
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("WWW-Authenticate")
    except urllib.error.URLError as e:
        raise AssertionError(f"ingest endpoint unreachable: {e}") from e


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
