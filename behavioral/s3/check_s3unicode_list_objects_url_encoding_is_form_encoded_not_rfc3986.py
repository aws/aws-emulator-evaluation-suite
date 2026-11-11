"""s3unicode-list-objects-url-encoding-is-form-encoded-not-rfc3986."""

from __future__ import annotations

import urllib.parse

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3unicode-list-objects-url-encoding-is-form-encoded-not-rfc3986"
GROUP = 'representation'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _list_keys(s3, bucket, prefix, **kwargs):
    """Every key under ``prefix``, paginated so membership is never asserted off page one."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix, **kwargs):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """EncodingType=url form-encodes keys (space to ``+``, ``+`` to ``%2B``), not RFC 3986.
    Only ``unquote_plus`` recovers the keys; plain ``unquote`` turns ``a b`` into existing ``a+b``.
    Delimiter and CommonPrefixes follow the same rule; the unencoded listing is byte-exact.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    emoji = "\U0001f600"
    prefix = "enc/"
    # One key per encoding hazard. The first two are the pair that collide under the wrong decoder.
    keys = {
        f"{prefix}a b.txt": b"space",
        f"{prefix}a+b.txt": b"literal-plus",
        f"{prefix}a%20b.txt": b"literal-percent",
        f"{prefix}a\nb.txt": b"newline",
        f"{prefix}a\x01b.txt": b"c0-control",
        f"{prefix}a{emoji}b.txt": b"astral",
    }
    assert len(keys) == 6, f"test setup error: expected 6 distinct keys, got {len(keys)}"
    for key, body in keys.items():
        s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- Positive control: with no EncodingType the keys come back raw and byte-exact, including
    #     the newline and the C0 control (S3 XML-escapes them rather than dropping them).
    raw = sorted(_list_keys(s3, bucket, prefix))
    assert raw == sorted(keys), (
        f"the unencoded ListObjectsV2 listing is not byte-exact: expected {sorted(keys)!r}, got "
        f"{raw!r}"
    )

    # --- EncodingType=url: every key is recoverable EXACTLY, with the form decoder.
    encoded = sorted(_list_keys(s3, bucket, prefix, EncodingType="url"))
    assert len(encoded) == len(keys), (
        f"the url-encoded listing returned {len(encoded)} keys, not {len(keys)}: {encoded!r}"
    )
    recovered = sorted(urllib.parse.unquote_plus(k) for k in encoded)
    assert recovered == sorted(keys), (
        f"unquote_plus over the url-encoded listing did not recover the stored keys: expected "
        f"{sorted(keys)!r}, got {recovered!r} from {encoded!r}"
    )

    # --- The transform is form-encoding, named byte for byte.
    by_recovered = {urllib.parse.unquote_plus(k): k for k in encoded}
    assert by_recovered[f"{prefix}a b.txt"] == f"{prefix}a+b.txt", (
        f"a space in a key was not encoded as '+': the stored key {prefix + 'a b.txt'!r} came back "
        f"as {by_recovered[prefix + 'a b.txt']!r}"
    )
    assert by_recovered[f"{prefix}a+b.txt"] == f"{prefix}a%2Bb.txt", (
        f"a literal '+' in a key was not encoded as '%2B': the stored key {prefix + 'a+b.txt'!r} "
        f"came back as {by_recovered[prefix + 'a+b.txt']!r}"
    )
    assert by_recovered[f"{prefix}a%20b.txt"] == f"{prefix}a%2520b.txt", (
        f"a literal '%' in a key was not encoded as '%25': the stored key "
        f"{prefix + 'a%20b.txt'!r} came back as {by_recovered[prefix + 'a%20b.txt']!r}"
    )
    enc_newline = by_recovered[f"{prefix}a\nb.txt"]
    assert enc_newline == f"{prefix}a%0Ab.txt", (
        f"a newline in a key was not encoded as '%0A': it came back as {enc_newline!r}"
    )
    enc_control = by_recovered[f"{prefix}a\x01b.txt"]
    assert enc_control == f"{prefix}a%01b.txt", (
        f"a C0 control in a key was not encoded as '%01': it came back as {enc_control!r}"
    )
    enc_astral = by_recovered[f"{prefix}a{emoji}b.txt"]
    assert enc_astral == f"{prefix}a%F0%9F%98%80b.txt", (
        f"the astral key was not encoded as its UTF-8 bytes: it came back as {enc_astral!r}"
    )

    # --- Effect absent, and the reason this matters: the RFC-3986 decoder does NOT recover the
    #     space key -- it silently produces the OTHER key that exists in this same bucket.
    encoded_space = by_recovered[f"{prefix}a b.txt"]
    rfc3986_decoded = urllib.parse.unquote(encoded_space)
    assert rfc3986_decoded != f"{prefix}a b.txt", (
        f"plain unquote recovered the space key {prefix + 'a b.txt'!r} from {encoded_space!r}, so "
        f"S3 is percent-encoding the space rather than form-encoding it"
    )
    assert rfc3986_decoded == f"{prefix}a+b.txt", (
        f"plain unquote of {encoded_space!r} yielded {rfc3986_decoded!r}; expected it to collide "
        f"with the literal-plus key {prefix + 'a+b.txt'!r}"
    )
    # The collision is real, not hypothetical: that other key holds a different body.
    collided = s3.get_object(Bucket=bucket, Key=rfc3986_decoded)["Body"].read()
    assert collided == b"literal-plus", (
        f"the key an RFC-3986 decoder would produce holds {collided!r}, not the literal-plus body; "
        f"the collision assertion is not measuring what it claims"
    )
    assert s3.get_object(Bucket=bucket, Key=f"{prefix}a b.txt")["Body"].read() == b"space", (
        "the space key no longer holds its own body"
    )

    # --- Delimiter and CommonPrefixes are encoded by the same rule, in the same response.
    enc_resp = s3.list_objects_v2(
        Bucket=bucket, Prefix=prefix, Delimiter="\n", EncodingType="url"
    )
    assert enc_resp["IsTruncated"] is False, (
        "the delimiter listing paged; this assertion needs the whole result in one response"
    )
    assert enc_resp["Delimiter"] == "%0A", (
        f"the echoed Delimiter was not url-encoded: got {enc_resp['Delimiter']!r}, expected '%0A'"
    )
    common = [cp["Prefix"] for cp in enc_resp.get("CommonPrefixes", [])]
    assert common == [f"{prefix}a%0A"], (
        f"CommonPrefixes was not url-encoded as expected: got {common!r}, expected "
        f"['{prefix}a%0A']"
    )
    assert urllib.parse.unquote_plus(common[0]) == f"{prefix}a\n", (
        f"the encoded common prefix does not decode back to the stored bytes: "
        f"{urllib.parse.unquote_plus(common[0])!r}"
    )

    # --- Positive control for the same two fields with no EncodingType: raw bytes, not encoded.
    raw_resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter="\n")
    assert raw_resp["IsTruncated"] is False, (
        "the unencoded delimiter listing paged; this assertion needs the whole result in one "
        "response"
    )
    assert raw_resp["Delimiter"] == "\n", (
        f"the unencoded listing altered the echoed Delimiter: got {raw_resp['Delimiter']!r}"
    )
    raw_common = [cp["Prefix"] for cp in raw_resp.get("CommonPrefixes", [])]
    assert raw_common == [f"{prefix}a\n"], (
        f"the unencoded CommonPrefixes is not byte-exact: got {raw_common!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
