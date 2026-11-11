"""native-ingest-endpoint-requires-basic-auth."""
from __future__ import annotations

import hashlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from behavioral_harness import tags

CHECK = "native-ingest-endpoint-requires-basic-auth"
GROUP = "native-protocol"
SERVICES = ["mediapackage"]

_PROPAGATION_DEADLINE_S = 60.0
_POLL_INTERVAL_S = 3.0


def _put_status_unauthenticated(ctx, url: str, body: bytes, timeout_s: float = 15.0) -> tuple[int, str | None]:
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=body, method="PUT", headers=route_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status, resp.headers.get("WWW-Authenticate")
    except urllib.error.HTTPError as err:
        return err.code, err.headers.get("WWW-Authenticate")


def _md5hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()  # noqa: S324 -- RFC 2617 Digest auth mandates MD5


def _put_status_digest(
    ctx, url: str, www_authenticate: str, username: str, password: str, body: bytes, timeout_s: float = 15.0
) -> int:
    """PUT with a real computed Digest response (RFC 2617), not Basic -- the ingest
    endpoint's WWW-Authenticate challenge is `Digest realm="WebDAV" ... qop="auth"`."""
    challenge = dict(re.findall(r'(\w+)="?([^",]+)"?', www_authenticate))
    realm = challenge["realm"]
    nonce = challenge["nonce"]
    qop = challenge.get("qop", "auth")
    uri = urllib.parse.urlsplit(url).path
    ha1 = _md5hex(f"{username}:{realm}:{password}")
    ha2 = _md5hex(f"PUT:{uri}")
    nc = "00000001"
    cnonce = _md5hex(f"cnonce:{nonce}")[:16]
    response = _md5hex(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
    header = (
        f'Digest username="{username}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
        f'qop="{qop}", nc={nc}, cnonce="{cnonce}", response="{response}", algorithm=MD5'
    )
    target_url, route_headers = ctx.endpoint_route(url)
    req = urllib.request.Request(target_url, data=body, method="PUT", headers={"Authorization": header, **route_headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return resp.status
    except urllib.error.HTTPError as err:
        return err.code


def _digest_put(ctx, url: str, username: str, password: str, body: bytes) -> int:
    _, challenge = _put_status_unauthenticated(ctx, url, body)
    assert challenge, "expected a WWW-Authenticate challenge on the 401 probe"
    return _put_status_digest(ctx, url, challenge, username, password, body)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The HLS ingest endpoint accepts a Digest-authenticated PUT with the channel's credentials (not 401),
    and answers 401 to the same PUT with a wrong password and to one with no credentials."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ingest-")
    created = mp.create_channel(Id=channel_id, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    ingest = created["HlsIngest"]["IngestEndpoints"][0]
    url = ingest["Url"]
    username = ingest["Username"]
    password = ingest["Password"]
    body = b"#EXTM3U\n#EXT-X-VERSION:3\n"

    # Positive control: correct credentials must authenticate. Freshly generated
    # credentials take a few seconds to propagate from the control plane to the
    # ingest edge fleet, so poll on a bounded deadline rather than trusting one shot.
    deadline = time.monotonic() + _PROPAGATION_DEADLINE_S
    status_correct = _digest_put(ctx, url, username, password, body)
    while status_correct == 401 and time.monotonic() < deadline:
        time.sleep(_POLL_INTERVAL_S)
        status_correct = _digest_put(ctx, url, username, password, body)
    assert status_correct != 401, (
        f"correct ingest credentials were still rejected as unauthenticated after "
        f"{_PROPAGATION_DEADLINE_S:.0f}s (status {status_correct})"
    )

    # With the endpoint live and honoring these credentials, a wrong password must be
    # specifically rejected -- not merely "not ready yet".
    status_wrong_pw = _digest_put(ctx, url, username, password + "-wrong", body)
    assert status_wrong_pw == 401, f"expected 401 with a wrong-password Digest response, got {status_wrong_pw}"

    # No credentials at all -> unauthenticated PUT is challenged with 401.
    status_no_auth, _ = _put_status_unauthenticated(ctx, url, body)
    assert status_no_auth == 401, f"expected 401 with no credentials, got {status_no_auth}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
