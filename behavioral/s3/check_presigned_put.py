"""presigned-put."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "presigned-put"
GROUP = 'presigned'
SERVICES = ['s3']

# An endpoint data-plane FAIL marker: a check detail containing this string is scored as a real
# fidelity failure, never dropped as a connection error.
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
    if ctx.region != "us-east-1":  # us-east-1 is the one region CreateBucket rejects a LocationConstraint for
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _s3_client(ctx, *, config):
    """An S3 client from ctx.client("s3") with ``config`` merged over the runner's."""
    return ctx.client("s3", config=config)


def _presign_client(ctx):
    """An S3 client for presigned URLs: SigV4 (s3v4) + regional virtual host.

    Forcing s3v4 makes X-Amz-Date / X-Amz-Credential exist (so tamper checks exercise them);
    virtual addressing pins the URL to the regional host (no 307); an IP-literal endpoint stays
    path-style.
    """
    from botocore.config import Config

    s3cfg = {"addressing_style": "virtual"}
    cfg = Config(
        signature_version="s3v4",
        s3=s3cfg,
        retries={"max_attempts": 1},
    )
    return _s3_client(ctx, config=cfg)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A presigned PUT URL allows uploading an object without credentials."""
    s3 = ctx.client("s3")
    import ssl
    import urllib.error
    import urllib.request

    bucket = _new_bucket(ctx, s3)
    content_type = "text/plain"
    url = _presign_client(ctx).generate_presigned_url(
        "put_object",
        Params={
            "Bucket": bucket,
            "Key": "presigned-upload.txt",
            "ContentType": content_type,
        },
        ExpiresIn=300,
    )
    upload_body = b"uploaded-via-presigned-put"
    req = urllib.request.Request(url, data=upload_body, method="PUT")
    req.add_header("Content-Type", content_type)
    verify = ctx.http_verify
    tls_context = ssl.create_default_context(cafile=verify) if isinstance(verify, str) else None
    # The URL is one the target itself just generated, so a target that will not accept the upload
    # is a fidelity failure. Marked because urlopen reports that as urllib's own transport wording
    # ("Connection refused", "timed out"), which reads like a network fault rather than a target
    # with no presigned-URL support.
    try:
        resp = urllib.request.urlopen(req, context=tls_context)
        status = resp.status
    except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:  # includes HTTPError: the upload was refused
        raise AssertionError(
            f"{DATAPLANE_MARKER}: presigned PUT URL did not accept the upload: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    assert status == 200, f"presigned PUT upload returned status {status}, expected 200"

    # Verify the object landed
    got = s3.get_object(Bucket=bucket, Key="presigned-upload.txt")["Body"].read()
    assert got == upload_body, (
        f"object body after presigned PUT was {got!r}, expected {upload_body!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
