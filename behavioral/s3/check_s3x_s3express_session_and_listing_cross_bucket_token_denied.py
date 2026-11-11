"""s3x-s3express-session-and-listing-cross-bucket-token-denied."""

from __future__ import annotations

from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "s3x-s3express-session-and-listing-cross-bucket-token-denied"
GROUP = 'directory_buckets'
SERVICES = ['s3']


# ===== helpers (self-contained) =====

# S3 Express One Zone Availability-Zone IDs per region. Zone IDs (not names) are physical and
# identical in every account, so this is a fact about AWS, not about any one account.
_S3EXPRESS_AZ_IDS = {
    "us-east-1": ["use1-az4", "use1-az5", "use1-az6"],
    "us-east-2": ["use2-az1", "use2-az2"],
    "us-west-2": ["usw2-az1", "usw2-az3", "usw2-az4"],
    "ap-south-1": ["aps1-az1", "aps1-az3"],
    "ap-northeast-1": ["apne1-az1", "apne1-az4"],
    "eu-central-1": ["euc1-az1", "euc1-az2"],
    "eu-west-1": ["euw1-az1", "euw1-az3"],
    "eu-north-1": ["eun1-az1", "eun1-az2", "eun1-az3"],
}


def _err(fn):
    """Call fn(); return (Error.Code, HTTP status, Error.Message) of the ClientError. Raise if it
    SUCCEEDS."""
    try:
        result = fn()
    except ClientError as exc:
        return (exc.response.get("Error", {}).get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Message"))
    brief = {k: v for k, v in (result or {}).items() if k not in ("ResponseMetadata", "Body")}
    raise AssertionError(f"expected the call to be refused, it succeeded: {brief!r}")


def _empty_and_delete(s3, bucket):
    """Abort every open MPU, delete every object, then delete the bucket."""
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for up in page.get("Uploads", []) or []:
            s3.abort_multipart_upload(Bucket=bucket, Key=up["Key"], UploadId=up["UploadId"])
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []) or []:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _directory_bucket(ctx, s3, prefix):
    """Create an S3 Express directory bucket, registering its teardown in the same breath."""
    azs = _S3EXPRESS_AZ_IDS.get(ctx.region)
    if not azs:
        raise AssertionError(f"S3 Express One Zone AZ IDs not known for region {ctx.region!r}")
    base = ctx.unique_name(prefix)
    last = None
    for az in azs:
        name = f"{base}--{az}--x-s3"
        try:
            s3.create_bucket(
                Bucket=name,
                CreateBucketConfiguration={
                    "Location": {"Type": "AvailabilityZone", "Name": az},
                    "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
                },
            )
        except ClientError as exc:
            last = exc
            continue
        ctx.on_cleanup(lambda b=name: _empty_and_delete(s3, b))
        return name
    raise AssertionError(f"could not create a directory bucket in any of {azs!r}: {last}")


class _PinnedSessionIdentity:
    """Stands in for botocore's S3ExpressIdentityCache and ALWAYS returns the one session it was
    given. botocore's own cache calls CreateSession whenever it holds no live session, which
    would silently swap in a fresh token; this one never calls anything."""

    def __init__(self, creds):
        self._creds = creds

    def get_credentials(self, *_args, **_kwargs):
        return self._creds


def _session_client(ctx, session):
    """An S3 client that signs every directory-bucket request with exactly ``session``'s
    CreateSession credentials (x-amz-s3session-token), and never re-mints.

    Returns (client, stats): stats["ops"] lists every operation the client sent, stats["pinned"]
    counts requests signed with the pinned session identity."""
    c = session["Credentials"]
    client = ctx.client("s3", creds={
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    })
    pinned = _PinnedSessionIdentity(Credentials(c["AccessKeyId"], c["SecretAccessKey"], c["SessionToken"]))
    stats = {"ops": [], "pinned": 0}

    def _pin(request, **_kwargs):
        signing = request.context.get("signing", {})
        if signing.get("identity_cache") is not None:
            signing["identity_cache"] = pinned
            stats["pinned"] += 1

    def _op(model, **_kwargs):
        stats["ops"].append(model.name)

    # Registered AFTER botocore's S3ExpressIdentityResolver (which runs at client build), so on
    # every before-sign it overrides the identity cache the resolver just installed.
    client.meta.events.register("before-sign.s3", _pin, unique_id=f"s3x-pin-{c['AccessKeyId']}")
    client.meta.events.register("before-call.s3", _op, unique_id=f"s3x-ops-{c['AccessKeyId']}")
    return client, stats

# ===== end helpers =====


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A ReadWrite CreateSession token minted for directory bucket A is AccessDenied on bucket B for
    GetObject and PutObject, leaving B's object untouched, while B's own token succeeds: a session
    token is scoped to the bucket that minted it, even for the principal owning both.
    """
    s3 = ctx.client("s3")
    bucket_a = _directory_bucket(ctx, s3, "sim2real-s3x-xa-")
    bucket_b = _directory_bucket(ctx, s3, "sim2real-s3x-xb-")
    key = "x/object.txt"
    s3.put_object(Bucket=bucket_a, Key=key, Body=b"bucket-a-original")
    s3.put_object(Bucket=bucket_b, Key=key, Body=b"bucket-b-original")

    tok_a, stats_a = _session_client(ctx, s3.create_session(Bucket=bucket_a, SessionMode="ReadWrite"))
    tok_b, stats_b = _session_client(ctx, s3.create_session(Bucket=bucket_b, SessionMode="ReadWrite"))

    # Positive control: token A is live and valid on the bucket it was minted for.
    home = tok_a.get_object(Bucket=bucket_a, Key=key)["Body"].read()
    assert home == b"bucket-a-original", f"token A could not read its own bucket: {home!r}"

    # The one thing under test: token A against bucket B.
    code, status, message = _err(lambda: tok_a.get_object(Bucket=bucket_b, Key=key))
    assert (code, status, message) == ("AccessDenied", 403, "Access Denied"), (
        f"bucket-A token GetObject on bucket B returned {(code, status, message)!r}, expected "
        "('AccessDenied', 403, 'Access Denied')"
    )
    code, status, message = _err(lambda: tok_a.put_object(Bucket=bucket_b, Key=key, Body=b"overwritten-by-a"))
    assert (code, status, message) == ("AccessDenied", 403, "Access Denied"), (
        f"bucket-A token PutObject on bucket B returned {(code, status, message)!r}, expected "
        "('AccessDenied', 403, 'Access Denied')"
    )

    # Effect absent, read through B's own token -- which is also the positive control that B is
    # reachable with a correctly scoped token.
    b_body = tok_b.get_object(Bucket=bucket_b, Key=key)["Body"].read()
    assert b_body == b"bucket-b-original", f"refused cross-bucket PutObject changed bucket B: {b_body!r}"
    tok_b.put_object(Bucket=bucket_b, Key=key, Body=b"overwritten-by-b")
    b_after = tok_b.get_object(Bucket=bucket_b, Key=key)["Body"].read()
    assert b_after == b"overwritten-by-b", f"bucket-B token PutObject did not take effect: {b_after!r}"

    for label, stats, n in (("A", stats_a, 3), ("B", stats_b, 3)):
        assert "CreateSession" not in stats["ops"], (
            f"the bucket-{label} session-pinned client minted its own session (ops {stats['ops']!r})"
        )
        assert stats["pinned"] == len(stats["ops"]) == n, (
            f"token {label}: expected {n} calls signed with the minted session, got pinned="
            f"{stats['pinned']} ops={stats['ops']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
