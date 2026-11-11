"""error-no-such-key."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "error-no-such-key"
GROUP = 'errors'
SERVICES = ['s3']

ERR_NO_SUCH_KEY = "NoSuchKey"

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
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return name


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a request real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetObject for a key that was never written returns NoSuchKey, on a bucket where GetObject
    for a real key demonstrably works — otherwise "rejects a missing key" is indistinguishable
    from "rejects every GetObject"."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    control_key = "control/exists.txt"
    control_body = b"sim2real-positive-control"
    s3.put_object(Bucket=bucket, Key=control_key, Body=control_body)

    got = s3.get_object(Bucket=bucket, Key=control_key)["Body"].read()
    assert got == control_body, f"positive control: expected {control_body!r}, got {got!r}"

    missing_key = "control/never-written.txt"
    code, message = _error_code(lambda: s3.get_object(Bucket=bucket, Key=missing_key))
    assert code == ERR_NO_SUCH_KEY, f"expected {ERR_NO_SUCH_KEY}, got {code!r}"
    assert message == "The specified key does not exist.", f"expected the exact {ERR_NO_SUCH_KEY} message, got {message!r}"

    # HeadObject is a distinct operation from GetObject; the miss must be visible through it too.
    head_code, head_message = _error_code(lambda: s3.head_object(Bucket=bucket, Key=missing_key))
    assert head_code == "404", f"expected 404 from HeadObject on a missing key, got {head_code!r}"
    assert head_message == "Not Found", f"expected 'Not Found' from HeadObject on a missing key, got {head_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
