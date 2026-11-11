"""delete-objects-empty-list-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-objects-empty-list-rejected"
GROUP = 'lifecycle'
SERVICES = ['s3']

_MALFORMED_XML_MESSAGE = (
    "The XML you provided was not well-formed or did not validate against our published schema"
)

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
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err(fn, what):
    """Call fn(); return the botocore Error dict it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"{what} succeeded; expected a refusal")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjects with zero keys is a malformed request and must be rejected with MalformedXML."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # --- Positive control: a well-formed DeleteObjects on this same bucket really works, so a
    # target that rejects every DeleteObjects call cannot pass merely because everything is denied.
    control_key = "control/a.txt"
    s3.put_object(Bucket=bucket, Key=control_key, Body=b"control")
    resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": control_key}], "Quiet": False})
    deleted = {d["Key"] for d in resp.get("Deleted", [])}
    assert deleted == {control_key}, f"expected {control_key!r} in Deleted, got {resp.get('Deleted')}"
    assert not resp.get("Errors"), f"expected no per-key errors, got {resp.get('Errors')}"
    control_err = _err(lambda: s3.get_object(Bucket=bucket, Key=control_key), "GetObject of the deleted control key")
    assert control_err.get("Code") == "NoSuchKey", (
        f"expected NoSuchKey reading back the control key after delete, got {control_err!r}"
    )
    assert control_err.get("Message") == "The specified key does not exist.", control_err.get("Message")

    # --- Break exactly one thing: an empty Objects list is malformed and can never become valid,
    # so this negative has no restore leg by construction.
    survivor_key = "survivor/b.txt"
    s3.put_object(Bucket=bucket, Key=survivor_key, Body=b"survivor")

    exc = None
    try:
        s3.delete_objects(Bucket=bucket, Delete={"Objects": []})
    except ClientError as e:
        exc = e
    assert exc is not None, "DeleteObjects with zero keys was accepted; the empty-batch rejection is not enforced"
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "MalformedXML", f"expected MalformedXML for an empty delete batch, got {code!r}"
    assert exc.response.get("Error", {}).get("Message") == _MALFORMED_XML_MESSAGE, exc.response.get("Error")
    assert status == 400, f"expected HTTP 400 for an empty delete batch, got {status!r}"

    # --- Effect absent, via an independent read at the destination: the malformed request must
    # not have touched the bucket's real contents.
    remaining = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert remaining == {survivor_key}, (
        f"an empty DeleteObjects must have no effect; expected only {survivor_key!r} to survive, "
        f"bucket now holds {sorted(remaining)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
