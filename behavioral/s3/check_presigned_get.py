"""presigned-get."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "presigned-get"
GROUP = 'presigned'
SERVICES = ['s3']

# An endpoint data-plane FAIL marker: a detail containing this string is a fidelity failure, not a
# connection error or a not-implemented answer.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A presigned GET URL returns the object content without credentials."""
    s3 = ctx.client("s3")
    import ssl
    import urllib.error
    import urllib.request

    bucket = _new_bucket(ctx, s3)
    body = b"presigned-test-content-sim2real"
    s3.put_object(Bucket=bucket, Key="presigned.txt", Body=body)

    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": "presigned.txt"},
        ExpiresIn=300,
    )
    # Fetch without any AWS credentials — the signature is in the URL.
    # The URL is one the target itself just generated, so a target that will not serve it is a
    # fidelity failure. Marked because urlopen reports that as urllib's own transport wording
    # ("Connection refused", "timed out"), which reads like a network fault rather than a target
    # with no presigned-URL support.
    verify = ctx.http_verify
    tls_context = ssl.create_default_context(cafile=verify) if isinstance(verify, str) else None
    try:
        resp = urllib.request.urlopen(url, context=tls_context)
        got = resp.read()
        status = resp.status
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # includes HTTPError: the URL did not serve
        raise AssertionError(
            f"{DATAPLANE_MARKER}: presigned GET URL did not serve the object: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    assert got == body, f"presigned GET returned {len(got)} bytes, expected {len(body)}"
    assert status == 200, f"presigned GET returned status {status}, expected 200"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
