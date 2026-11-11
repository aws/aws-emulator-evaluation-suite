"""object-metadata-unicode-value-round-trip."""
from __future__ import annotations

import base64

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "object-metadata-unicode-value-round-trip"
GROUP = "representation"
SERVICES = ["s3"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An RFC 2047 encoded-word metadata value (how S3 carries non-ASCII metadata) comes back
    byte-identical from HeadObject and GetObject and decodes to the original Unicode text; after delete
    the key is NoSuchKey/404 and can be reused."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-s3meta-uni-")
    key = "unicode-metadata.txt"
    _create_bucket(ctx, bucket)

    unicode_value = "\u00c4M\u00c4Z\u00d5\u00d1 S3 \u65e5\u672c\u8a9e"  # "ÄMÄZÕÑ S3 日本語"
    ascii_value = "PLAIN-ASCII-VALUE"

    # Caller-side RFC 2047 mail-safe ("B" = base64) encoding -- this is the
    # ASCII-only representation that is actually transmitted on the wire.
    encoded_value = "=?UTF-8?B?" + base64.b64encode(unicode_value.encode("utf-8")).decode("ascii") + "?="

    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=b"payload",
        Metadata={"nonascii": encoded_value, "ascii": ascii_value},
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["Metadata"]["nonascii"] == encoded_value, (
        f"expected the RFC-2047 encoded-word to survive byte-identical, "
        f"sent {encoded_value!r}, got {head['Metadata']['nonascii']!r}"
    )
    assert head["Metadata"]["ascii"] == ascii_value
    assert _decode_rfc2047(head["Metadata"]["nonascii"]) == unicode_value

    got = s3.get_object(Bucket=bucket, Key=key)
    assert got["Metadata"]["nonascii"] == encoded_value, (
        f"expected the RFC-2047 encoded-word to survive byte-identical, "
        f"sent {encoded_value!r}, got {got['Metadata']['nonascii']!r}"
    )
    assert got["Metadata"]["ascii"] == ascii_value
    assert _decode_rfc2047(got["Metadata"]["nonascii"]) == unicode_value
    got["Body"].close()

    # Cleanup already deletes this object -- make that delete a free negative:
    # prove it is genuinely gone via an independent read, that a second
    # operation on the dead key also fails, and that the key is reusable.
    s3.delete_object(Bucket=bucket, Key=key)
    try:
        s3.get_object(Bucket=bucket, Key=key)
        raise AssertionError("expected GetObject to raise NoSuchKey after DeleteObject")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "NoSuchKey", f"expected NoSuchKey for a deleted object, got {code!r}"
        assert message == "The specified key does not exist.", f"unexpected NoSuchKey message: {message!r}"
    try:
        s3.head_object(Bucket=bucket, Key=key)
        raise AssertionError("expected HeadObject to raise 404 after DeleteObject")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "404", f"expected 404 for a deleted object, got {code!r}"
        # HeadObject carries no error body; the message is the HTTP reason phrase.
        assert message == "Not Found", f"unexpected HeadObject 404 message: {message!r}"

    s3.put_object(Bucket=bucket, Key=key, Body=b"reused", Metadata={"ascii": ascii_value})
    reused = s3.head_object(Bucket=bucket, Key=key)
    assert reused["Metadata"]["ascii"] == ascii_value, "a deleted key must be reusable"


def _create_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))


def _decode_rfc2047(encoded: str) -> str:
    """Decode a '=?UTF-8?B?...?=' RFC 2047 encoded-word back to text."""
    assert encoded.startswith("=?UTF-8?B?") and encoded.endswith("?="), encoded
    b64_part = encoded[len("=?UTF-8?B?") : -len("?=")]
    return base64.b64decode(b64_part).decode("utf-8")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
