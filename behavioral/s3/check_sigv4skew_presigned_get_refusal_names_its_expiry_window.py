"""sigv4skew-presigned-get-refusal-names-its-expiry-window."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sigv4skew-presigned-get-refusal-names-its-expiry-window"
GROUP = 'sigv4-skew'
SERVICES = ['s3']

# ===== helpers (self-contained) =====

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
    if location != "us-east-1":  # us-east-1 is the one region CreateBucket rejects a LocationConstraint for
        params["CreateBucketConfiguration"] = {"LocationConstraint": location}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    """A presigned GET serves the object before its expiry, then is refused naming that expiry.

    Both outcomes are read against S3's own clock, not this host's, with the refusal polled for.
    """
    import time

    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    payload = b"sigv4skew-presigned-expiry-payload"
    key = "sigv4skew/expiring.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)

    expires_in = 15
    url = _presign_client(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=expires_in
    )
    query = dict(_signed_query(url))
    assert query.get("X-Amz-Expires") == str(expires_in), (
        f"the presigned URL must carry the expiry we asked for as a signed parameter; "
        f"X-Amz-Expires was {query.get('X-Amz-Expires')!r} in {sorted(query)!r}"
    )
    signed_at = _amz_instant(query["X-Amz-Date"])
    expires_at = signed_at + datetime.timedelta(seconds=expires_in)

    # Usable BEFORE its expiry -- and the target's own Date header proves it was before.
    status, headers, got = _http("GET", url)
    assert status == 200, f"a presigned GET inside its window must serve the object, got {status}"
    assert got == payload, f"presigned GET served {got!r}, expected {payload!r}"
    served_at = _http_date(headers["date"])
    assert served_at < expires_at, (
        f"the target served this URL at {served_at!r}, which is not before the expiry it signed "
        f"({expires_at!r}); the positive half of this check never happened"
    )

    # Refused AFTER it: poll for the refusal to arrive rather than asserting any deadline.
    deadline = time.monotonic() + 180.0
    status, _, body = 200, {}, b""
    while time.monotonic() < deadline:
        time.sleep(3.0)
        status, _, body = _http("GET", url)
        if status != 200:
            break
    assert status == 403, (
        f"a presigned GET must stop being honoured once its expiry passes; the URL still answered "
        f"{status} after polling past {expires_at!r}"
    )
    err = _error_xml(body)
    assert err["Code"] == "AccessDenied", (
        f"expected AccessDenied for an expired presigned GET, got {err['Code']!r}"
    )
    assert err["Message"] == "Request has expired", (
        f"the refusal must say the request expired, got {err['Message']!r}"
    )

    # The refusal NAMES the expiry, to the second: the window asked for, and the instant it ended.
    assert err["X-Amz-Expires"] == str(expires_in), (
        f"the refusal must name the signed window; X-Amz-Expires was {err['X-Amz-Expires']!r}, "
        f"expected {str(expires_in)!r}"
    )
    assert err["Expires"] == expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"), (
        f"the named expiry must be X-Amz-Date + X-Amz-Expires to the second: expected "
        f"{expires_at.strftime('%Y-%m-%dT%H:%M:%SZ')!r}, got {err['Expires']!r}"
    )
    assert err["ServerTime"] >= err["Expires"], (
        f"a 'Request has expired' refusal must report a ServerTime at or after the expiry it names; "
        f"got ServerTime={err['ServerTime']!r} against Expires={err['Expires']!r}"
    )

    # It was the URL's expiry and nothing else: a URL signed now serves the same bytes.
    fresh = _presign_client(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=300
    )
    status, _, got = _http("GET", fresh)
    assert status == 200, f"a freshly presigned GET of the same object returned {status}"
    assert got == payload, f"freshly presigned GET served {got!r}, expected {payload!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
