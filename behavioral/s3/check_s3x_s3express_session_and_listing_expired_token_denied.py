"""s3x-s3express-session-and-listing-expired-token-denied."""

from __future__ import annotations

import time
from email.utils import parsedate_to_datetime

from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "s3x-s3express-session-and-listing-expired-token-denied"
GROUP = 'directory_buckets'
SERVICES = ['s3']

#: Seconds before the server-declared Expiration during which a refusal counts as PREMATURE.
_EARLY_SLACK_S = 15
#: Seconds past the server-declared Expiration within which the refusal must have appeared.
_LATE_CEILING_S = 120
_POLL_INTERVAL_S = 10


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


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateSession.html
@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CreateSession token is honoured for its server-declared lifetime and AccessDenied once its
    Expiration passes (GetObject and PutObject, the refused write leaving no object), while a fresh
    token succeeds; a refusal more than _EARLY_SLACK_S before Expiration fails as premature.
    """
    s3 = ctx.client("s3")
    bucket = _directory_bucket(ctx, s3, "sim2real-s3x-exp-")
    key = "exp/object.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"live-object")

    session = s3.create_session(Bucket=bucket, SessionMode="ReadWrite")
    started = time.monotonic()
    server_now = parsedate_to_datetime(session["ResponseMetadata"]["HTTPHeaders"]["date"])
    ttl = (session["Credentials"]["Expiration"] - server_now).total_seconds()
    assert 240 <= ttl <= 330, f"CreateSession token lifetime is {ttl:.0f}s, expected about 300s"
    old, stats = _session_client(ctx, session)

    # Positive control at mint time: the token works.
    first = old.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert first == b"live-object", f"fresh session token could not read the object: {first!r}"

    # Poll through the token's life until it is refused (bounded past Expiration).
    honoured = 1
    while True:
        elapsed = time.monotonic() - started
        try:
            old.get_object(Bucket=bucket, Key=key)["Body"].read()
        except ClientError as exc:
            refused = (exc.response.get("Error", {}).get("Code"),
                       exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                       exc.response.get("Error", {}).get("Message"))
            break
        honoured += 1
        if elapsed > ttl + _LATE_CEILING_S:
            raise AssertionError(
                f"token still honoured {elapsed:.0f}s after mint, {elapsed - ttl:.0f}s past its "
                f"Expiration ({honoured} successful reads)"
            )
        time.sleep(_POLL_INTERVAL_S)

    assert elapsed >= ttl - _EARLY_SLACK_S, (
        f"token refused {refused!r} only {elapsed:.0f}s after mint, before its {ttl:.0f}s lifetime"
    )
    assert refused == ("AccessDenied", 403, "Access Denied"), (
        f"GetObject with the expired session token returned {refused!r}, expected "
        "('AccessDenied', 403, 'Access Denied')"
    )

    code, status, message = _err(lambda: old.put_object(Bucket=bucket, Key="exp/late-write.txt", Body=b"late"))
    assert (code, status, message) == ("AccessDenied", 403, "Access Denied"), (
        f"PutObject with the expired session token returned {(code, status, message)!r}, expected "
        "('AccessDenied', 403, 'Access Denied')"
    )

    # Effect absent: the refused write created nothing (read with the runner's own identity).
    keys = sorted(o["Key"] for o in s3.list_objects_v2(Bucket=bucket, Prefix="exp/").get("Contents", []) or [])
    assert keys == [key], f"refused expired-token PutObject left keys {keys!r}, expected only [{key!r}]"

    # Positive control: a freshly minted token on the identical GetObject succeeds.
    fresh, fresh_stats = _session_client(ctx, s3.create_session(Bucket=bucket, SessionMode="ReadWrite"))
    again = fresh.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert again == b"live-object", f"freshly minted token could not read the object: {again!r}"

    for label, st in (("expired", stats), ("fresh", fresh_stats)):
        assert "CreateSession" not in st["ops"], (
            f"the {label} session-pinned client minted its own session (ops {st['ops']!r}) -- the "
            f"expired-token path was not exercised"
        )
        assert st["pinned"] == len(st["ops"]), (
            f"{label}: not every call was signed with the pinned session: pinned={st['pinned']} "
            f"ops={st['ops']!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
