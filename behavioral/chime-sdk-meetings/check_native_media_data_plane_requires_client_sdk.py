"""native-media-data-plane-requires-client-sdk."""
from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "native-media-data-plane-requires-client-sdk"
GROUP = "native-protocol"
SERVICES = ["chime-sdk-meetings"]


@tags("axis:happy-path", "cap:c1", "cap:c6", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """The SignalingUrl in CreateMeeting's MediaPlacement completes a TLS handshake and answers an
    unauthenticated WebSocket upgrade on its path with an HTTP/1.1 4xx, so the advertised signaling
    endpoint is live rather than a URL that points nowhere or a catch-all 2xx server."""
    chime = ctx.client("chime-sdk-meetings")
    meeting = chime.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2real-token-"),
        # MediaRegion picks where the meeting's media/signaling is hosted, independent of
        # ctx.region (the chime-sdk-meetings control-plane endpoint); us-east-1 is always
        # a valid Chime SDK media region.
        MediaRegion="us-east-1",
        ExternalMeetingId=ctx.unique_name("sim2real-ext-"),
    )["Meeting"]
    meeting_id = meeting["MeetingId"]
    ctx.on_cleanup(lambda: chime.delete_meeting(MeetingId=meeting_id))

    signaling_url = meeting["MediaPlacement"]["SignalingUrl"]
    parsed = urlparse(signaling_url)
    assert not (p := ctx.published_url_mismatch(signaling_url, labels=("chime",), websocket=True)), p
    port = parsed.port or 443

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    host, port = ctx.endpoint_host(parsed.hostname, port)
    response = _tls_websocket_probe(host, port, path)
    assert response, (
        f"no bytes received from live TLS/WebSocket handshake against "
        f"{parsed.hostname}:{port}{path} (from SignalingUrl {signaling_url!r}) -- "
        "MediaPlacement points at an endpoint that isn't actually serving the "
        "media/signaling protocol"
    )
    status_line = response.split(b"\r\n", 1)[0]
    assert status_line.startswith(b"HTTP/1.1 "), (
        f"expected an HTTP/1.1 response line from the media signaling endpoint, got "
        f"{response[:64]!r}"
    )
    status_code = int(status_line.split(b" ")[1])
    assert 400 <= status_code < 500, (
        f"expected the real signaling control endpoint to reject our unauthenticated, "
        f"non-conforming WebSocket upgrade with a 4xx protocol-level refusal (that is what "
        f"a genuine MediaPlacement gives an unauthenticated probe), got {status_code} from "
        f"{parsed.hostname}:{port}{path} -- either nothing is really listening on the "
        f"advertised control path, or something answered every path generically instead of "
        f"speaking the signaling protocol"
    )


def _tls_websocket_probe(host: str, port: int, path: str = "/", timeout: float = 8.0) -> bytes:
    """Open a real TLS connection to host:port and issue a WebSocket upgrade request,
    returning whatever bytes the server sends back (empty bytes on no response)."""
    # A raw TLS socket to an endpoint_host address does not verify the server's identity.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = context.wrap_socket(raw, server_hostname=host)
        try:
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "Connection: Upgrade\r\n"
                "Upgrade: websocket\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: c2ltMnJlYWwtcHJvYmUta2V5\r\n"
                "\r\n"
            ).encode("ascii")
            tls.sendall(request)
            tls.settimeout(timeout)
            return tls.recv(512)
        finally:
            tls.close()
    finally:
        try:
            raw.close()
        except OSError:
            pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
