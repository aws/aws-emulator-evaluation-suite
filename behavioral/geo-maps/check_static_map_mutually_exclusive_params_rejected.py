"""static-map-mutually-exclusive-params-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "static-map-mutually-exclusive-params-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-maps"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStaticMap with BoundingBox and Zoom together is rejected with ValidationException and its exact
    message, while BoundingBox alone returns an image of the requested size.
    """
    client = ctx.client("geo-maps")
    bbox = "-123.17075,49.26959,-123.08125,49.31429"

    def bad_call():
        client.get_static_map(
            FileName="map", Width=300, Height=300, Style="Satellite", BoundingBox=bbox, Zoom=10.0
        )

    code, message = _error_code(bad_call)
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "'Zoom' must not be set when 'BoundingBox' is set."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    control = client.get_static_map(
        FileName="map", Width=300, Height=300, Style="Satellite", BoundingBox=bbox
    )
    control_blob = control["Blob"].read()
    assert len(control_blob) > 0, "positive control returned an empty blob"
    assert control["ContentType"].startswith(
        "image/"
    ), f"expected an image content type, got {control['ContentType']!r}"
    actual_width, actual_height = _image_dimensions(control_blob)
    assert (actual_width, actual_height) == (
        300,
        300,
    ), f"expected a 300x300 image, got {actual_width}x{actual_height}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("expected the mutually-exclusive call to be rejected, but it succeeded")


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
