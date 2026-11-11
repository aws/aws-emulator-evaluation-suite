"""s3unicode-rfc3986-reserved-chars-in-a-key-are-literal."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-rfc3986-reserved-chars-in-a-key-are-literal"
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


def _list_keys(s3, bucket, prefix):
    """Every key under ``prefix``, paginated so membership is never asserted off page one."""
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=prefix):
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
    """RFC-3986 reserved characters in a key are stored, listed and prefix-matched literally: ``+``
    is not a space and ``%20`` is three characters, so neither space spelling finds the object.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    prefix = "res/"
    # Every RFC-3986 reserved character that S3 permits in a key, plus a literal percent
    # sequence, a literal plus and a literal space.
    tail = "a+b c%20d?e#f&g=h i@j!k'l(m)n,o$p;q=r[s]t\"u~v.txt"
    key = f"{prefix}{tail}"
    body = b"reserved-character-payload\x00\xff"

    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- The bytes round-trip.
    got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got == body, (
        f"GetObject on the reserved-character key did not return the body byte-for-byte: sent "
        f"{body!r}, got {got!r}"
    )

    # --- The key lists back with identical bytes.
    listed = _list_keys(s3, bucket, prefix)
    assert listed == [key], (
        f"ListObjectsV2 did not return exactly the reserved-character key: expected [{key!r}], got "
        f"{listed!r}"
    )
    assert listed[0].encode("utf-8") == key.encode("utf-8"), (
        f"the listed key's bytes differ from the written key's: listed "
        f"{listed[0].encode('utf-8')!r}, written {key.encode('utf-8')!r}"
    )

    # --- A SERVER-SIDE prefix match over the reserved bytes selects it. This is the assertion a
    #     client-side comparison cannot fake: the prefix itself carries '+', ' ' and '%20'.
    server_prefix = f"{prefix}a+b c%20"
    matched = _list_keys(s3, bucket, server_prefix)
    assert matched == [key], (
        f"a server-side Prefix of {server_prefix!r} did not select the key: expected [{key!r}], got "
        f"{matched!r}"
    )

    # --- Effect absent 1: the '+'-as-space spelling is not an alias (form-decoding bug).
    key_plus_as_space = key.replace("a+b", "a b")
    assert key_plus_as_space != key, "test setup error: the '+'-as-space variant equals the key"
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_plus_as_space))
    assert exc is not None, (
        f"the key spelled with a space where the stored key has a '+' resolves to an object: "
        f"{key_plus_as_space!r} -- '+' is being form-decoded as a space"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the '+'-as-space spelling, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Effect absent 2: the '%20'-as-space spelling is not an alias (double-decoding bug).
    key_pct_as_space = key.replace("c%20d", "c d")
    assert key_pct_as_space != key, "test setup error: the '%20'-as-space variant equals the key"
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_pct_as_space))
    assert exc is not None, (
        f"the key spelled with a space where the stored key has the three literal characters '%20' "
        f"resolves to an object: {key_pct_as_space!r} -- the key is being percent-decoded twice"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the '%20'-as-space spelling, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Positive control: the literal key is still exactly one object holding exactly its bytes.
    assert _list_keys(s3, bucket, prefix) == [key], (
        f"probing the corrupted spellings changed the bucket: {_list_keys(s3, bucket, prefix)!r}"
    )
    final = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert final == body, (
        f"the reserved-character object was altered by the 404 probes: expected {body!r}, got "
        f"{final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
