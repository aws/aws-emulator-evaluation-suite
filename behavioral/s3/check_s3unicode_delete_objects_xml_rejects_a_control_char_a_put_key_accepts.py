"""s3unicode-delete-objects-xml-rejects-a-control-char-a-put-key-accepts."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3unicode-delete-objects-xml-rejects-a-control-char-a-put-key-accepts"
GROUP = 'errors'
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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A vertical-tab (U+000B) key works in PutObject/DeleteObject; DeleteObjects says MalformedXML.

    U+000B is not an XML 1.0 Char; tab, LF and emoji keys batch-delete fine; the VT object survives.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    emoji = "\U0001f600"
    prefix = "del/"
    key_vt = f"{prefix}a\x0bb.txt"       # VERTICAL TAB: illegal in XML 1.0
    key_tab = f"{prefix}a\tb.txt"        # TAB: legal in XML 1.0
    key_lf = f"{prefix}a\nb.txt"         # LINE FEED: legal in XML 1.0
    key_astral = f"{prefix}a{emoji}b.txt"
    legal = [key_tab, key_lf, key_astral]
    body = b"batch-delete-payload"

    for key in [key_vt] + legal:
        s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- PutObject accepted all four, including the vertical tab: the key itself is legal.
    stored = sorted(_list_keys(s3, bucket, prefix))
    assert stored == sorted([key_vt] + legal), (
        f"PutObject did not store all four control-character keys byte-exactly: expected "
        f"{sorted([key_vt] + legal)!r}, got {stored!r}"
    )
    assert s3.head_object(Bucket=bucket, Key=key_vt)["ContentLength"] == len(body), (
        f"the vertical-tab key {key_vt!r} is not addressable via HeadObject, so the asymmetry this "
        f"check measures cannot be established"
    )

    # --- Positive control, in the batch API: the three XML-legal keys delete in one DeleteObjects
    #     call and are echoed back byte-exactly.
    ok = s3.delete_objects(
        Bucket=bucket, Delete={"Objects": [{"Key": k} for k in legal], "Quiet": False}
    )
    assert ok.get("Errors", []) == [], (
        f"DeleteObjects reported per-key errors for XML-legal keys: {ok.get('Errors')!r}"
    )
    echoed = sorted(d["Key"] for d in ok.get("Deleted", []))
    assert echoed == sorted(legal), (
        f"DeleteObjects did not echo the XML-legal keys byte-exactly: expected {sorted(legal)!r}, "
        f"got {echoed!r}"
    )
    for key in legal:
        exc = _client_error(lambda k=key: s3.head_object(Bucket=bucket, Key=k))
        assert exc is not None, f"the batch delete reported {key!r} deleted but it still exists"
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
            f"expected HTTP 404 for the batch-deleted key {key!r}, got "
            f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
        )

    # --- Break exactly one thing: the same batch API, one key holding a vertical tab.
    exc = _client_error(
        lambda: s3.delete_objects(
            Bucket=bucket, Delete={"Objects": [{"Key": key_vt}], "Quiet": False}
        )
    )
    assert exc is not None, (
        f"DeleteObjects accepted the vertical-tab key {key_vt!r} in its XML body; real S3 refuses "
        f"it, and any response echoing U+000B would not be well-formed XML"
    )
    code = exc.response.get("Error", {}).get("Code")
    assert code == "MalformedXML", (
        f"expected MalformedXML for a DeleteObjects body containing U+000B, got {code!r}"
    )
    assert exc.response.get("Error", {}).get("Message") == (
        "The XML you provided was not well-formed or did not validate against our published schema"
    ), exc.response.get("Error")
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f"expected HTTP 400 for MalformedXML, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Effect absent: the rejected batch deleted nothing.
    assert _list_keys(s3, bucket, prefix) == [key_vt], (
        f"after the rejected batch the prefix should still hold exactly {key_vt!r}, got "
        f"{_list_keys(s3, bucket, prefix)!r}"
    )
    survivor = s3.get_object(Bucket=bucket, Key=key_vt)["Body"].read()
    assert survivor == body, (
        f"the vertical-tab object was damaged by the rejected batch delete: expected {body!r}, got "
        f"{survivor!r}"
    )

    # --- The asymmetry, stated: the SAME key deletes cleanly through the URL-path transport.
    s3.delete_object(Bucket=bucket, Key=key_vt)
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key_vt))
    assert exc is not None, (
        f"DeleteObject did not remove {key_vt!r}; the vertical tab is unrepresentable in the batch "
        f"API but must be deletable through the URL path"
    )
    assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 after DeleteObject on the vertical-tab key, got "
        f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert _list_keys(s3, bucket, prefix) == [], (
        f"the prefix is not empty after every key was deleted: "
        f"{_list_keys(s3, bucket, prefix)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
