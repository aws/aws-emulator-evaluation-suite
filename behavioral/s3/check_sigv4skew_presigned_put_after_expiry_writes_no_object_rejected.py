"""sigv4skew-presigned-put-after-expiry-writes-no-object-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sigv4skew-presigned-put-after-expiry-writes-no-object-rejected"
GROUP = 'sigv4-skew'
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


def _new_bucket(ctx, s3, region=None, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    location = region or ctx.region
    if location != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": location}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _http(method, url, headers=None, data=None):
    """Raw HTTP request; returns (status, lowercased-headers, body-bytes). 4xx/5xx captured."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body


def _error_code(fn):
    """The AWS error code ``fn`` raised. An unexpected SUCCESS raises rather than returning falsy:
    an emulator accepting input real AWS refuses is the strongest signal this suite can carry, and
    returning "" here would downgrade it to an error-code mismatch that reads like a naming
    difference."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("the call SUCCEEDED where real AWS raises an error")


def _error_xml(body):
    """Parse an S3 REST error body structurally into {element-tag: text}."""
    from xml.etree import ElementTree

    root = ElementTree.fromstring(body)
    assert root.tag == "Error", f"expected an <Error> document, got <{root.tag}>: {body[:200]!r}"
    return {child.tag: (child.text or "") for child in root}


def _server_now(client, bucket):
    """S3's OWN current UTC instant, read from the Date response header.

    Every offset in this check is measured against the target's clock rather than this host's:
    a runner whose clock drifts would otherwise turn "inside the skew window" into a coin flip,
    and the skew window is the subject.
    """
    import email.utils

    headers = client.head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPHeaders"]
    date = headers.get("date")
    assert date, f"S3 returned no Date header to read its clock from; headers were {sorted(headers)!r}"
    return email.utils.parsedate_to_datetime(date).replace(tzinfo=None)


def _presign_client(ctx):
    """An S3 client for presigned URLs: SigV4 (s3v4) + regional virtual host.

    Forcing s3v4 makes X-Amz-Date / X-Amz-Expires exist as signed query parameters (so this check
    has something to grade); virtual addressing pins the URL to the regional host (no 307); an
    IP-literal endpoint stays path-style.
    """
    from botocore.config import Config

    return ctx.client(
        "s3",
        config=Config(
            signature_version="s3v4",
            s3={"addressing_style": "virtual"},
            retries={"max_attempts": 1},
        ),
    )


def _signed_query(url):
    """The presigned URL's query as an ordered list of (key, value), parsed, not split."""
    from urllib.parse import parse_qsl, urlsplit

    return parse_qsl(urlsplit(url).query, keep_blank_values=True)


def _rebuild(url, pairs):
    """Re-assemble ``url`` with ``pairs`` as its query, re-encoding exactly what SigV4 signed."""
    from urllib.parse import urlencode, urlsplit, urlunsplit

    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(pairs, quote_via=_quote_v4), "")
    )


def _quote_v4(string, safe="", encoding=None, errors=None):
    """SigV4's query encoding: unreserved characters stay literal, everything else percent-encoded."""
    from urllib.parse import quote

    return quote(string, safe="-_.~")


def _http_date(value):
    """An HTTP Date header as a naive UTC datetime."""
    import email.utils

    return email.utils.parsedate_to_datetime(value).replace(tzinfo=None)


def _amz_instant(value):
    """An X-Amz-Date (``YYYYMMDDTHHMMSSZ``) as a naive UTC datetime."""
    import datetime

    return datetime.datetime.strptime(value, "%Y%m%dT%H%M%SZ")


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A presigned PUT used after its expiry is refused and leaves no object behind, while the same
    mechanism used inside its window really writes the bytes. Never attempted before the expiry,
    so an accepted early write cannot make the later absence unprovable.
    """
    import time

    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    presigner = _presign_client(ctx)
    payload = b"sigv4skew-presigned-put-payload"
    late_key, control_key = "sigv4skew/late.txt", "sigv4skew/in-time.txt"

    # Positive control: the same mechanism, used inside its window, really writes the bytes.
    control_url = presigner.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": control_key}, ExpiresIn=600
    )
    status, _, body = _http("PUT", control_url, data=payload)
    assert status == 200, f"a presigned PUT inside its window must succeed, got {status}: {body[:300]!r}"
    stored = s3.get_object(Bucket=bucket, Key=control_key)["Body"].read()
    assert stored == payload, f"the presigned PUT stored {stored!r}, expected {payload!r}"

    expires_in = 15
    late_url = presigner.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": late_key}, ExpiresIn=expires_in
    )
    query = dict(_signed_query(late_url))
    assert query.get("X-Amz-Expires") == str(expires_in), (
        f"X-Amz-Expires was {query.get('X-Amz-Expires')!r}, expected {str(expires_in)!r}"
    )
    expires_at = _amz_instant(query["X-Amz-Date"]) + datetime.timedelta(seconds=expires_in)

    # Poll the TARGET's clock past the expiry it signed; never touch the URL before then.
    deadline = time.monotonic() + 180.0
    server_time = _server_now(s3, bucket)
    while server_time <= expires_at and time.monotonic() < deadline:
        time.sleep(3.0)
        server_time = _server_now(s3, bucket)
    assert server_time > expires_at, (
        f"S3's clock never passed the expiry {expires_at!r} within the poll window; last read "
        f"{server_time!r}"
    )

    status, _, body = _http("PUT", late_url, data=payload)
    assert status == 403, (
        f"a presigned PUT used after {expires_at!r} must be refused 403, got {status}: "
        f"{body[:300]!r}"
    )
    err = _error_xml(body)
    assert err["Code"] == "AccessDenied", (
        f"expected AccessDenied for an expired presigned PUT, got {err['Code']!r}"
    )
    assert err["Message"] == "Request has expired", (
        f"the refusal must say the request expired, got {err['Message']!r}"
    )
    assert err["Expires"] == expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"), (
        f"the refusal must name X-Amz-Date + X-Amz-Expires to the second: expected "
        f"{expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')!r}, got {err['Expires']!r}"
    )

    # Effect absent: nothing was written under the late key.
    code = _error_code(lambda: s3.get_object(Bucket=bucket, Key=late_key))
    assert code == "NoSuchKey", (
        f"the expired presigned PUT must not have written {late_key!r}; get_object answered {code!r}"
    )
    listed = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="sigv4skew/"):
        listed.update(o["Key"] for o in page.get("Contents", []))
    assert listed == {control_key}, (
        f"only the in-time control object may exist under this check's own prefix; the bucket holds "
        f"{sorted(listed)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
