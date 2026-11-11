"""glyphs-invalid-unicode-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "glyphs-invalid-unicode-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["geo-maps"]


@tags("axis:rejection", "cap:c5", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetGlyphs with a FontUnicodeRange outside the '<start>-<end>.pbf' path pattern fails with an HTTP 404
    and returns no glyphs, while a well-formed range for the same font stack returns glyph data.
    """
    client = ctx.client("geo-maps")

    def bad_call():
        client.get_glyphs(FontStack="Amazon Ember Regular", FontUnicodeRange="not-a-range")

    code = _error_code(bad_call)
    assert code == "404", f"expected a routing-level 404, got {code!r}"

    control = client.get_glyphs(
        FontStack="Amazon Ember Regular", FontUnicodeRange="0-255.pbf"
    )
    control_blob = control["Blob"].read()
    assert len(control_blob) > 0, "positive control returned an empty glyph blob"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
