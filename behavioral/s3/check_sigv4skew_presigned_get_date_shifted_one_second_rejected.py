"""sigv4skew-presigned-get-date-shifted-one-second-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sigv4skew-presigned-get-date-shifted-one-second-rejected"
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
    # us-east-1 is S3's default region; CreateBucket rejects an explicit LocationConstraint for it.
    if location != "us-east-1":
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
    """A presigned GET's X-Amz-Date shifted by ONE SECOND, still inside the signed window, fails
    SignatureDoesNotMatch and never "Request has expired".

    A sibling check shifts the same field to a long-past instant and gets AccessDenied instead.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    payload = b"sigv4skew-one-second-payload"
    key = "sigv4skew/one-second.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)

    signed_for = 600
    url = _presign_client(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=signed_for
    )

    # Positive control first: the untampered URL serves the object.
    status, _, got = _http("GET", url)
    assert status == 200, f"the untampered presigned GET must serve the object, got {status}"
    assert got == payload, f"untampered presigned GET served {got!r}, expected {payload!r}"

    # Break exactly one thing, by exactly one second, well inside the signed window.
    pairs = _signed_query(url)
    original = dict(pairs)["X-Amz-Date"]
    shifted = (_amz_instant(original) + datetime.timedelta(seconds=1)).strftime("%Y%m%dT%H%M%SZ")
    assert shifted != original, f"the shift must change the date; both read {original!r}"
    tampered_pairs = [(k, shifted if k == "X-Amz-Date" else v) for k, v in pairs]
    assert sum(1 for a, b in zip(pairs, tampered_pairs) if a != b) == 1, (
        f"exactly one parameter may differ; {pairs!r} vs {tampered_pairs!r}"
    )
    status, _, body = _http("GET", _rebuild(url, tampered_pairs))
    assert status == 403, (
        f"shifting a signed X-Amz-Date by one second must be refused 403, got {status}: "
        f"{body[:300]!r}"
    )
    err = _error_xml(body)
    assert err["Code"] == "SignatureDoesNotMatch", (
        f"a one-second shift is still inside the {signed_for}s window, so the refusal must come "
        f"from the signature; got {err['Code']!r} ({err.get('Message')!r})"
    )
    # The expiry window was not reached, so the refusal names the signature and never expiry.
    assert err["Message"] == (
        "The request signature we calculated does not match the signature you provided. "
        "Check your key and signing method."
    ), f"unexpected SignatureDoesNotMatch message {err['Message']!r}"

    # Effect absent: nothing was served with the refusal.
    assert payload not in body, (
        f"the refusal body must not contain the object's bytes; got {body[:300]!r}"
    )

    # The mechanism: the shifted second is what S3 hashed, in both the canonical request and the
    # string to sign -- which is what "bound to the second" means.
    assert f"X-Amz-Date={shifted}" in err["CanonicalRequest"], (
        f"S3's canonical request must carry the shifted date X-Amz-Date={shifted}; it read "
        f"{err['CanonicalRequest']!r}"
    )
    assert err["StringToSign"].split("\n")[1] == shifted, (
        f"the string to sign's timestamp line must be the shifted date {shifted!r}, got "
        f"{err['StringToSign'].split(chr(10))[1]!r}"
    )

    # And the original URL is unharmed.
    status, _, got = _http("GET", url)
    assert status == 200, f"the untampered URL must still serve the object, got {status}"
    assert got == payload, f"untampered presigned GET served {got!r} after the tamper"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
