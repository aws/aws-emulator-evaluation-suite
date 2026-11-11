"""presigned-put-requires-every-signed-header-and-refuses-an-over-week-expiry."""

from __future__ import annotations

import urllib.error
import urllib.request
from xml.etree import ElementTree

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "presigned-put-requires-every-signed-header-and-refuses-an-over-week-expiry"
GROUP = "presigned"
SERVICES = ["s3"]

_WEEK_S = 604800
_BODY = b"presigned-put-payload-signed-headers-matter"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A presigned PUT omitting a signed header is refused, as is X-Amz-Expires over one week.

    Omitting the signed SSE header gives 403 SignatureDoesNotMatch and stores nothing; resending it
    succeeds. Expiry of 604801 s gives 400 AuthorizationQueryParametersError.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # ---------------- (a) signed headers ----------------
    control_key = "presigned/control.bin"
    subject_key = "presigned/subject.bin"
    sse_header = {"x-amz-server-side-encryption": "AES256"}

    control_url = _presign_client(ctx).generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": control_key, "ServerSideEncryption": "AES256"},
        ExpiresIn=900,
    )
    assert "X-Amz-SignedHeaders" in control_url, (
        f"the presigned PUT URL carries no X-Amz-SignedHeaders query parameter, so there is no "
        f"signed header to omit: {control_url.split('?', 1)[0]}?…"
    )
    assert "server-side-encryption" in control_url.lower(), (
        "X-Amz-SignedHeaders does not name x-amz-server-side-encryption, so the header this check "
        f"omits was never signed: {control_url}"
    )

    # Beat 1 — positive control. Without it, "the header-less PUT was refused" cannot be told from
    # "every presigned PUT is refused".
    status, body = _http(ctx, "PUT", control_url, headers=sse_header, data=_BODY)
    assert status == 200, (
        f"the presigned PUT that resends every signed header returned {status}: {body[:200]!r}"
    )
    head = s3.head_object(Bucket=bucket, Key=control_key)
    assert head.get("ServerSideEncryption") == "AES256", (
        f"the control object reports ServerSideEncryption {head.get('ServerSideEncryption')!r}, "
        "expected 'AES256' — the signed header was accepted but not applied"
    )
    assert s3.get_object(Bucket=bucket, Key=control_key)["Body"].read() == _BODY, (
        "the control object's bytes do not match the presigned PUT body"
    )

    # Beat 2 — break exactly one thing: omit the signed header. Same URL shape, same body.
    subject_url = _presign_client(ctx).generate_presigned_url(
        "put_object",
        Params={"Bucket": bucket, "Key": subject_key, "ServerSideEncryption": "AES256"},
        ExpiresIn=900,
    )
    status, body = _http(ctx, "PUT", subject_url, data=_BODY)
    assert status == 403, (
        f"a presigned PUT that OMITS the signed x-amz-server-side-encryption header returned "
        f"{status}, expected 403 — the signature is not being verified over the signed headers, so "
        f"any holder of the URL can upload without the encryption the issuer required: {body[:200]!r}"
    )
    assert _xml_error(body) == ("SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided. Check your key and signing method."), (
        f"the refused presigned PUT returned no SignatureDoesNotMatch error: {body[:300]!r}"
    )

    # Beat 3 — effect absent, by an independent read.
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=subject_key)) == "404", (
        f"{subject_key!r} exists after the presigned PUT that omitted a signed header was refused"
    )

    # Beat 4 — restore: the identical URL, with the header put back, succeeds.
    status, body = _http(ctx, "PUT", subject_url, headers=sse_header, data=_BODY)
    assert status == 200, (
        f"re-sending the SAME presigned URL with the signed header restored returned {status}: "
        f"{body[:200]!r} — the refusal above was not about the missing header"
    )
    assert s3.get_object(Bucket=bucket, Key=subject_key)["Body"].read() == _BODY, (
        f"{subject_key!r} does not hold the presigned PUT body after the restore leg"
    )

    # ---------------- (b) the one-week expiry ceiling ----------------
    # An always-invalid-input negative: X-Amz-Expires can never become legal, so there is no
    # restore beat by construction. The positive control is still mandatory.
    valid_get = _presign_client(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": control_key}, ExpiresIn=900
    )
    status, body = _http(ctx, "GET", valid_get)
    assert status == 200 and body == _BODY, (
        f"the in-window presigned GET returned {status} with {body[:120]!r}; expected 200 and the "
        "object's bytes"
    )

    over_week_get = _presign_client(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": control_key}, ExpiresIn=_WEEK_S + 1
    )
    assert f"X-Amz-Expires={_WEEK_S + 1}" in over_week_get, (
        f"the URL does not carry X-Amz-Expires={_WEEK_S + 1}, so the ceiling is not being tested: "
        f"{over_week_get}"
    )
    status, body = _http(ctx, "GET", over_week_get)
    assert status == 400, (
        f"a presigned GET with X-Amz-Expires={_WEEK_S + 1} returned {status}, expected 400 — SigV4 "
        f"query authentication caps the window at {_WEEK_S}s, and a target that ignores the cap "
        f"issues effectively permanent URLs: {body[:200]!r}"
    )
    assert _xml_error(body) == ("AuthorizationQueryParametersError", (
        f"X-Amz-Expires must be less than a week (in seconds); that is, the given X-Amz-Expires "
        f"must be less than {_WEEK_S} seconds"
    )), (
        f"the over-a-week presigned GET returned no AuthorizationQueryParametersError error: "
        f"{body[:300]!r}"
    )
    assert _BODY not in body, (
        "the refused over-a-week presigned GET still returned the object's bytes"
    )



def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; teardown only."""
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
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # region-pinned: CreateBucket rejects LocationConstraint there
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _s3_client(ctx, *, config):
    """An S3 client from ctx.client("s3") with ``config`` merged over the runner's."""
    return ctx.client("s3", config=config)


def _presign_client(ctx):
    """An S3 client for presigned URLs: SigV4 (s3v4) + virtual-hosted addressing.

    Without s3v4 the default presigner may emit query auth with no X-Amz-SignedHeaders; virtual
    addressing pins the regional host (no 307).
    """
    from botocore.config import Config

    cfg = Config(
        signature_version="s3v4",
        s3={"addressing_style": "virtual"},
        retries={"max_attempts": 1},
    )
    return _s3_client(ctx, config=cfg)


def _error_code(fn) -> str:
    """The botocore Error.Code (or HTTP status for a code-less HEAD) of fn(); RAISES if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code and not code.isdigit():
            return code
        return str(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown"))
    raise AssertionError("the call was expected to fail and it succeeded")


def _xml_error(body: bytes) -> tuple[str | None, str | None]:
    """The (Code, Message) of an S3 XML error body; None for a part the body does not carry."""
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return None, None
    return root.findtext("Code"), root.findtext("Message")


def _http(ctx, method: str, url: str, headers=None, data=None):
    """Raw HTTP to ``url`` on the target; returns (status, body). 4xx/5xx are answers, not errors."""
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, method=method, data=data)
    for k, v in {**route, **(headers or {})}.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
