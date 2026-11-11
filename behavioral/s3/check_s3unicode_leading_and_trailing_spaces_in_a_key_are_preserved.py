"""s3unicode-leading-and-trailing-spaces-in-a-key-are-preserved."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-leading-and-trailing-spaces-in-a-key-are-preserved"
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
    """Every key under ``prefix``, across all pages."""
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
    """Leading, trailing, both and no spaces make four distinct keys: S3 never trims whitespace.

    Each key has a distinct body, so a trimming store would collapse them and cross the bodies.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    prefix = "sp/"
    keys = {
        f"{prefix} x.txt": b"body-LEADING-space",
        f"{prefix}x .txt": b"body-TRAILING-space",
        f"{prefix} x .txt": b"body-BOTH-spaces",
        f"{prefix}x.txt": b"body-NO-space",
    }

    # --- Setup assertion: the four spellings really are four distinct strings that share one
    #     stripped form, so a trimming implementation must collapse them.
    assert len(keys) == 4, f"test setup error: expected 4 distinct keys, got {len(keys)}"
    stripped = {k.replace(" ", "") for k in keys}
    assert stripped == {f"{prefix}x.txt"}, (
        f"test setup error: the four keys do not share one space-free form, they reduce to "
        f"{stripped!r}"
    )

    for key, body in keys.items():
        s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- All four identities exist, byte-exactly, and nothing else does.
    listed = sorted(_list_keys(s3, bucket, prefix))
    assert listed == sorted(keys), (
        f"the four space-variant keys are not four distinct objects: expected {sorted(keys)!r}, got "
        f"{listed!r} -- a shorter listing means the keys were trimmed and objects were overwritten"
    )
    assert sorted(k.encode("utf-8") for k in listed) == sorted(
        k.encode("utf-8") for k in keys
    ), (
        f"the listed keys' bytes differ from the written keys': listed "
        f"{[k.encode('utf-8') for k in listed]!r}"
    )

    # --- Each key returns ITS OWN body. A collapse crosses the pairing.
    for key, body in keys.items():
        got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert got == body, (
            f"the key {key!r} returned the wrong body: expected {body!r}, got {got!r} -- the "
            f"space-variant keys are aliases of one another"
        )

    # --- A server-side Prefix that INCLUDES the leading space selects only the two keys that
    #     start with one. This cannot be faked client-side.
    lead_prefix = f"{prefix} "
    lead_matched = sorted(_list_keys(s3, bucket, lead_prefix))
    assert lead_matched == sorted([f"{prefix} x.txt", f"{prefix} x .txt"]), (
        f"a server-side Prefix of {lead_prefix!r} did not select exactly the two leading-space "
        f"keys: got {lead_matched!r}"
    )

    # --- Transition: deleting the space-free key leaves the three space-bearing ones whole.
    s3.delete_object(Bucket=bucket, Key=f"{prefix}x.txt")
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=f"{prefix}x.txt"))
    assert exc is not None, f"the key {prefix + 'x.txt'!r} survived its own delete"
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for the deleted space-free key, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    survivors = sorted(_list_keys(s3, bucket, prefix))
    expected = sorted(k for k in keys if k != f"{prefix}x.txt")
    assert survivors == expected, (
        f"deleting the space-free key disturbed the space-bearing ones: expected {expected!r}, got "
        f"{survivors!r}"
    )
    for key in expected:
        got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        assert got == keys[key], (
            f"the surviving key {key!r} lost its body: expected {keys[key]!r}, got {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
