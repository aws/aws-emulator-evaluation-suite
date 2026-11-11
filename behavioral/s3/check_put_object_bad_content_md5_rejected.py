"""put-object-bad-content-md5-rejected."""

from __future__ import annotations

import base64
import hashlib

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-object-bad-content-md5-rejected"
GROUP = 'data_integrity'
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
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _expect_client_error(fn):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with a mismatched Content-MD5 is rejected with BadDigest and stores nothing;
    the same bytes with the correct Content-MD5 are accepted, so the refusal is the digest's.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "baddigest.txt"
    body = b"the real payload"
    correct_md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    wrong_md5 = base64.b64encode(hashlib.md5(body + b"x").digest()).decode()
    assert wrong_md5 != correct_md5, "the wrong digest collided with the correct one"

    # --- Break exactly one thing: the Content-MD5 header, over otherwise valid bytes.
    exc = _expect_client_error(lambda: s3.put_object(
        Bucket=bucket, Key=key, Body=body, ContentMD5=wrong_md5
    ))
    error = exc.response.get("Error", {})
    code = error.get("Code")
    message = error.get("Message")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "BadDigest", f"expected BadDigest for a mismatched Content-MD5, got {code!r}"
    assert message == "The Content-MD5 you specified did not match what we received.", (
        f"expected the exact BadDigest message for a mismatched Content-MD5, got {message!r}"
    )
    assert status == 400, f"expected HTTP 400 for BadDigest, got {status!r}"

    # --- Effect absent: nothing was stored at the key.
    missing = _expect_client_error(lambda: s3.head_object(Bucket=bucket, Key=key))
    missing_code = missing.response.get("Error", {}).get("Code")
    missing_status = missing.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert missing_status == 404, (
        f"HeadObject after the BadDigest refusal returned {missing_status!r}, expected 404"
    )
    assert missing_code == "404", (
        f"HeadObject after the BadDigest refusal returned code {missing_code!r}, expected '404'"
    )
    missing_message = missing.response.get("Error", {}).get("Message")
    assert missing_message == "Not Found", (
        f"HeadObject after the BadDigest refusal said {missing_message!r}, expected 'Not Found'"
    )
    listed = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed += [o["Key"] for o in page.get("Contents", [])]
    assert listed == [], f"the bucket holds {listed!r} after the refused PUT; it must be empty"

    # --- POSITIVE CONTROL: the identical bytes at the identical key, with the correct
    # MD5-computed Content-MD5, must be accepted.
    stored = s3.put_object(Bucket=bucket, Key=key, Body=body, ContentMD5=correct_md5)
    assert stored["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the byte-identical PutObject with a correct Content-MD5 was not accepted: "
        f"{stored['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    got = s3.get_object(Bucket=bucket, Key=key)
    got_body = got["Body"].read()
    assert got_body == body, (
        f"the stored object is {got_body!r}, want the positive control's {body!r}"
    )
    assert got["ETag"] == f'"{hashlib.md5(body).hexdigest()}"', (
        f"the stored object's ETag is {got['ETag']!r}; for a single-part, unencrypted upload "
        f"it must equal the hex MD5 the client computed over the same bytes, "
        f'"{hashlib.md5(body).hexdigest()}"'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
