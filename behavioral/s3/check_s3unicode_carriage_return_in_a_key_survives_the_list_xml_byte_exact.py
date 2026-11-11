"""s3unicode-carriage-return-in-a-key-survives-the-list-xml-byte-exact."""

from __future__ import annotations

import urllib.parse

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-carriage-return-in-a-key-survives-the-list-xml-byte-exact"
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
    """Every key under ``prefix``, across all pages."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix, **kwargs):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CR (U+000D) in a key lists back as CR, not LF; the CR and LF keys are two distinct objects.

    XML parsers normalise a literal CR to LF, so S3 must escape it as &#13;; EncodingType=url gives
    %0D.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    prefix = "cr/"
    key_cr = f"{prefix}a\rb.txt"
    key_lf = f"{prefix}a\nb.txt"
    body_cr = b"body-CARRIAGE-RETURN"
    body_lf = b"body-LINE-FEED"

    assert key_cr != key_lf and key_cr.replace("\r", "\n") == key_lf, (
        f"test setup error: {key_cr!r} and {key_lf!r} do not differ in exactly the CR/LF byte"
    )

    # --- Only the CR key exists at first, so the LF spelling 404ing proves they are distinct.
    s3.put_object(Bucket=bucket, Key=key_cr, Body=body_cr)
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_lf))
    assert exc is not None, (
        f"the line-feed spelling {key_lf!r} resolves to an object while only the carriage-return "
        f"key was written; CR is being folded to LF"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the line-feed spelling, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- The unencoded listing returns the carriage return itself, which the response XML can only
    #     achieve by escaping it as &#13;.
    listed = _list_keys(s3, bucket, prefix)
    assert listed == [key_cr], (
        f"ListObjectsV2 did not return the carriage-return key byte-exactly: expected "
        f"[{key_cr!r}], got {listed!r} -- a line feed here means the key was written into the "
        f"response XML unescaped and the parser normalised it"
    )
    assert listed[0].encode("utf-8") == key_cr.encode("utf-8"), (
        f"the listed key's bytes differ from the written key's: listed "
        f"{listed[0].encode('utf-8')!r}, written {key_cr.encode('utf-8')!r}"
    )

    # --- Independent confirmation over the transport with no XML-escaping question: %0D, not %0A.
    encoded = _list_keys(s3, bucket, prefix, EncodingType="url")
    assert encoded == [f"{prefix}a%0Db.txt"], (
        f"EncodingType=url did not report the key's CR as %0D: got {encoded!r}"
    )
    assert urllib.parse.unquote_plus(encoded[0]) == key_cr, (
        f"the url-encoded key does not decode back to the carriage-return key: decoded "
        f"{urllib.parse.unquote_plus(encoded[0])!r}, stored {key_cr!r}"
    )

    # --- Both spellings now coexist as two objects with their own bodies.
    s3.put_object(Bucket=bucket, Key=key_lf, Body=body_lf)
    both = sorted(_list_keys(s3, bucket, prefix))
    assert both == sorted([key_cr, key_lf]), (
        f"the CR and LF keys are not two distinct objects: expected {sorted([key_cr, key_lf])!r}, "
        f"got {both!r}"
    )
    got_cr = s3.get_object(Bucket=bucket, Key=key_cr)["Body"].read()
    assert got_cr == body_cr, (
        f"the carriage-return key returned the wrong body: expected {body_cr!r}, got {got_cr!r}"
    )
    got_lf = s3.get_object(Bucket=bucket, Key=key_lf)["Body"].read()
    assert got_lf == body_lf, (
        f"the line-feed key returned the wrong body: expected {body_lf!r}, got {got_lf!r}"
    )

    # --- Transition: deleting the LF key leaves the CR key whole.
    s3.delete_object(Bucket=bucket, Key=key_lf)
    assert _list_keys(s3, bucket, prefix) == [key_cr], (
        f"deleting the line-feed key disturbed the carriage-return key: "
        f"{_list_keys(s3, bucket, prefix)!r}"
    )
    survivor = s3.get_object(Bucket=bucket, Key=key_cr)["Body"].read()
    assert survivor == body_cr, (
        f"the carriage-return object lost its body: expected {body_cr!r}, got {survivor!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
