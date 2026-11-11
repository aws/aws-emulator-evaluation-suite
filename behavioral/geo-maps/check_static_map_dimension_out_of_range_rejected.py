"""static-map-dimension-out-of-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "static-map-dimension-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-maps"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStaticMap must reject a Width above the documented 1400px maximum with
    ValidationException and must not render any image for it, while a compliant Width
    still succeeds in the same file (positive control)."""
    client = ctx.client("geo-maps")

    def bad_call():
        client.get_static_map(
            FileName="map",
            Width=2000,
            Height=300,
            Style="Satellite",
            Center="-123.108,49.295",
            Zoom=10.0,
        )

    code, message = _error_code(bad_call)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "'Width' must not be greater than 1400"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    control = client.get_static_map(
        FileName="map",
        Width=300,
        Height=300,
        Style="Satellite",
        Center="-123.108,49.295",
        Zoom=10.0,
    )
    control_blob = control["Blob"].read()
    assert len(control_blob) > 0, "positive control returned an empty image blob"
    actual_width, actual_height = _image_dimensions(control_blob)
    assert (actual_width, actual_height) == (300, 300), (
        f"positive control requested 300x300 but decoded image is "
        f"{actual_width}x{actual_height}"
    )


def _error_code(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING an out-of-range Width real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects Width=2000 (max 1400), but the call SUCCEEDED and returned {result!r}"
    )


def _image_dimensions(blob: bytes) -> tuple[int, int]:
    if blob[:8] == b"\x89PNG\r\n\x1a\n":
        width = int.from_bytes(blob[16:20], "big")
        height = int.from_bytes(blob[20:24], "big")
        return width, height
    if blob[:2] == b"\xff\xd8":
        idx = 2
        n = len(blob)
        while idx + 4 <= n:
            if blob[idx] != 0xFF:
                idx += 1
                continue
            marker = blob[idx + 1]
            if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
                idx += 2
                continue
            length = int.from_bytes(blob[idx + 2 : idx + 4], "big")
            if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
                height = int.from_bytes(blob[idx + 5 : idx + 7], "big")
                width = int.from_bytes(blob[idx + 7 : idx + 9], "big")
                return width, height
            idx += 2 + length
        raise ValueError("no SOF marker found in JPEG blob")
    raise ValueError(f"unrecognized image format, magic bytes={blob[:8]!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
