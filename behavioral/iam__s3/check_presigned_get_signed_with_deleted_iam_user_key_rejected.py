"""presigned-get-signed-with-deleted-iam-user-key-rejected."""
from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "presigned-get-signed-with-deleted-iam-user-key-rejected"
GROUP = "presigned"
SERVICES = ["iam", "s3"]


def _ignore(codes, fn):
    """Run a teardown call, tolerating only the error ``codes`` of an already-removed resource."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in codes:
            raise


def _delete_bucket(client, bucket):
    """Empty a bucket (every version and delete marker) then delete it."""
    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
            client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    client.delete_bucket(Bucket=bucket)


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-xsvc-bkt-")
    params = {"Bucket": name}
    # us-east-1 is the one region whose CreateBucket refuses a LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _delete_user_policy_safely(ctx, user_name, policy_name):
    _ignore(("NoSuchEntity",), lambda: ctx.client("iam").delete_user_policy(
        UserName=user_name, PolicyName=policy_name))


def _delete_access_key_safely(ctx, user_name, access_key_id):
    _ignore(("NoSuchEntity",), lambda: ctx.client("iam").delete_access_key(
        UserName=user_name, AccessKeyId=access_key_id))


def _delete_user_safely(ctx, user_name):
    _ignore(("NoSuchEntity",), lambda: ctx.client("iam").delete_user(UserName=user_name))


def _presign_client_for(ctx, creds):
    """An S3 client SigV4-presigning as ``creds``, single attempt so the check's poll owns retries.
    Path-style keeps the regional host; the default global host mismatches the credential scope."""
    cfg = Config(signature_version="s3v4", s3={"addressing_style": "path"},
                 retries={"max_attempts": 1})
    return ctx.client("s3", config=cfg, creds=creds)


def _xml_field(body: bytes, field: str) -> str | None:
    """The text of the first <field> element of an S3 XML error body, or None."""
    import re

    m = re.search(rf"<{field}>([^<]*)</{field}>".encode(), body)
    return m.group(1).decode() if m else None


def _http(method, url):
    """Raw HTTP request; returns (status, lowercased-headers, body-bytes). 4xx/5xx captured."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A presigned GET whose signing access key is deleted before the URL expires is rejected with
    403 InvalidAccessKeyId, while the object itself stays readable.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html
    """
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _new_bucket(ctx, s3)
    key_name = "object-a.txt"
    body = b"content-of-a"
    s3.put_object(Bucket=bucket, Key=key_name, Body=body)

    user_name = ctx.unique_name("sim2real-xsvc-presign-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_safely(ctx, user_name))

    policy_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/{key_name}",
                }
            ],
        }
    )
    iam.put_user_policy(UserName=user_name, PolicyName="allow-get", PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: _delete_user_policy_safely(ctx, user_name, "allow-get"))

    access_key = iam.create_access_key(UserName=user_name)["AccessKey"]
    access_key_id = access_key["AccessKeyId"]
    # The body deletes this key; this reaps it if an earlier assertion aborts first.
    ctx.on_cleanup(lambda: _delete_access_key_safely(ctx, user_name, access_key_id))

    creds = {"aws_access_key_id": access_key_id, "aws_secret_access_key": access_key["SecretAccessKey"]}

    # Positive control, same key, same URL: wait out IAM propagation and prove the live key is
    # accepted before deleting it -- otherwise a later 403 could just mean the key never worked.
    deadline = time.monotonic() + 60.0
    url = ""
    control_status, control_body = 0, b""
    while True:
        url = _presign_client_for(ctx, creds).generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key_name}, ExpiresIn=600
        )
        control_status, _, control_body = _http("GET", url)
        if control_status != 403 or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert control_status == 200, (
        f"positive control failed: expected 200 for the live key, got {control_status}: "
        f"{control_body[:200]!r}"
    )
    assert control_body == body, f"positive control failed: expected {body!r}, got {control_body[:200]!r}"

    # The URL's own 600 s expiry has not passed.
    iam.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)

    # Revocation is eventually consistent: reads right after DeleteAccessKey can still succeed.
    deadline = time.monotonic() + 90.0
    status, got = 0, b""
    while True:
        status, _, got = _http("GET", url)
        if status == 403 or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert status == 403, (
        f"expected 403 for a presigned GET signed with a deleted access key, got {status}: "
        f"{got[:200]!r}"
    )
    error = (_xml_field(got, "Code"), _xml_field(got, "Message"))
    expected = (
        "InvalidAccessKeyId",
        "The AWS Access Key Id you provided does not exist in our records.",
    )
    assert error == expected, f"expected the S3 error {expected!r}, got {error!r} ({got[:300]!r})"

    # Effect-absent: the deleted key cannot read the object; the object itself is unaffected.
    direct = s3.get_object(Bucket=bucket, Key=key_name)["Body"].read()
    assert direct == body, f"object must be unaffected by the rejected presigned GET, got {direct[:200]!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
