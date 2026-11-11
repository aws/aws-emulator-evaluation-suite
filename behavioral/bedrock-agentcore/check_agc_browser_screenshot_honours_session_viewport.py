"""agc-browser-screenshot-honours-session-viewport."""
from __future__ import annotations

import struct

from behavioral_harness import tags

CHECK = "agc-browser-screenshot-honours-session-viewport"
GROUP = "server-side"
SERVICES = ["bedrock-agentcore"]

_IDENTIFIER = "aws.browser.v1"  # AWS-managed built-in Browser tool; no control-plane Browser
# resource has to be created first.

# Two shapes, neither of them a plausible service default, so a fixed-size renderer cannot pass
# both. Both are inside the model's declared ViewPort range (320-3840 x 240-2160).
_SMALL = {"width": 800, "height": 600}
_LARGE = {"width": 1280, "height": 1024}


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Two concurrent browser sessions started with different viewports return distinct session ids, and an
    InvokeBrowser screenshot from each is a PNG whose IHDR width and height equal that session's viewport."""
    client = ctx.client("bedrock-agentcore")

    small_id = _start(ctx, client, _SMALL)
    large_id = _start(ctx, client, _LARGE)
    assert small_id != large_id, (
        f"two StartBrowserSession calls returned the same session id {small_id!r}"
    )

    small_png = _screenshot(client, small_id)
    large_png = _screenshot(client, large_id)

    small_dims = _png_dimensions(small_png)
    large_dims = _png_dimensions(large_png)

    assert small_dims == (_SMALL["width"], _SMALL["height"]), (
        f"session started with viewPort {_SMALL} rendered a {small_dims[0]}x{small_dims[1]} PNG"
    )
    assert large_dims == (_LARGE["width"], _LARGE["height"]), (
        f"session started with viewPort {_LARGE} rendered a {large_dims[0]}x{large_dims[1]} PNG"
    )
    # The two are genuinely per-session, not one global setting the second start overwrote.
    assert small_dims != large_dims, (
        f"both sessions rendered at {small_dims!r}, so the viewport is not session-scoped"
    )


def _start(ctx, client, view_port):
    """Start a browser session at *view_port* and register its teardown before anything else."""
    session = client.start_browser_session(
        browserIdentifier=_IDENTIFIER,
        name=ctx.unique_name("sim2real-br-vp-")[:100],
        sessionTimeoutSeconds=300,
        viewPort=view_port,
    )
    session_id = session["sessionId"]
    ctx.on_cleanup(lambda: client.stop_browser_session(
        browserIdentifier=_IDENTIFIER, sessionId=session_id))
    return session_id


def _screenshot(client, session_id):
    """The PNG bytes of one screenshot action, or an AssertionError naming what came back."""
    resp = client.invoke_browser(
        browserIdentifier=_IDENTIFIER,
        sessionId=session_id,
        action={"screenshot": {"format": "PNG"}},
    )
    result = (resp.get("result") or {}).get("screenshot")
    assert result is not None, (
        f"no screenshot member in the InvokeBrowser result: {sorted((resp.get('result') or {}))!r}"
    )
    assert result["status"] == "SUCCESS", (
        f"screenshot status was {result['status']!r}, error={result.get('error')!r}"
    )
    data = result.get("data")
    assert data is not None, f"screenshot reported SUCCESS with no data: {result!r}"
    return data.read() if hasattr(data, "read") else bytes(data)


def _png_dimensions(raw):
    """(width, height) parsed out of a PNG's IHDR, asserting the container as it goes.

    Parsed structurally rather than trusted: the length and the chunk type are checked before the
    two big-endian uint32s are read, so a non-PNG blob fails with a message that says so instead
    of silently yielding whatever four bytes sat at offset 16.
    """
    assert raw[:8] == b"\x89PNG\r\n\x1a\n", (
        f"not a PNG: first 8 bytes were {raw[:8]!r} ({len(raw)} bytes total)"
    )
    (length,) = struct.unpack(">I", raw[8:12])
    assert raw[12:16] == b"IHDR", f"first PNG chunk is {raw[12:16]!r}, expected IHDR"
    assert length == 13, f"IHDR declares {length} bytes, the PNG spec fixes it at 13"
    width, height = struct.unpack(">II", raw[16:24])
    assert width > 0 and height > 0, f"IHDR declares a {width}x{height} image"
    return width, height


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
