"""sigv4skew-presigned-get-altered-expires-param-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sigv4skew-presigned-get-altered-expires-param-rejected"
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
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    location = region or ctx.region
    # us-east-1 is S3's default region; CreateBucket rejects an explicit LocationConstraint for it.
    if location != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": location}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": "true"}]})
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
    """An S3 client for presigned URLs: s3v4 makes X-Amz-Date/X-Amz-Expires signed query
    parameters; virtual addressing pins the regional host (no 307).
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
    """Widening only X-Amz-Expires on a presigned GET yields 403 SignatureDoesNotMatch and no bytes;
    S3's echoed canonical request carries the tampered value, and the original URL still works.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    payload = b"sigv4skew-altered-param-payload"
    key = "sigv4skew/signed-param.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=payload)

    signed_for = 300
    url = _presign_client(ctx).generate_presigned_url(
        "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=signed_for
    )

    # Positive control first: the untampered URL serves the object.
    status, _, got = _http("GET", url)
    assert status == 200, f"the untampered presigned GET must serve the object, got {status}"
    assert got == payload, f"untampered presigned GET served {got!r}, expected {payload!r}"

    # Break exactly one thing: double the expiry window, leave every other pair untouched.
    pairs = _signed_query(url)
    assert ("X-Amz-Expires", str(signed_for)) in pairs, (
        f"expected X-Amz-Expires={signed_for} among the signed parameters, got {pairs!r}"
    )
    widened = str(signed_for * 2)
    tampered_pairs = [
        (k, widened if k == "X-Amz-Expires" else v) for k, v in pairs
    ]
    assert sum(1 for a, b in zip(pairs, tampered_pairs) if a != b) == 1, (
        f"exactly one parameter may differ; {pairs!r} vs {tampered_pairs!r}"
    )
    tampered = _rebuild(url, tampered_pairs)
    status, _, body = _http("GET", tampered)
    assert status == 403, (
        f"widening a signed X-Amz-Expires must be refused 403, got {status}: {body[:300]!r}"
    )
    err = _error_xml(body)
    assert err["Code"] == "SignatureDoesNotMatch", (
        f"expected SignatureDoesNotMatch, got {err['Code']!r} ({err.get('Message')!r})"
    )
    assert err["Message"] == (
        "The request signature we calculated does not match the signature you provided. "
        "Check your key and signing method."
    ), f"unexpected SignatureDoesNotMatch message {err['Message']!r}"

    # Effect absent: no object bytes were served with the refusal.
    assert payload not in body, (
        f"the refusal body must not contain the object's bytes; got {body[:300]!r}"
    )

    # The mechanism, not just the code: the tampered value entered the canonical request S3 signed,
    # and the signature it compared against is the one the URL still carries unchanged.
    assert f"X-Amz-Expires={widened}" in err["CanonicalRequest"], (
        f"S3's canonical request must contain the tampered X-Amz-Expires={widened}, proving the "
        f"parameter is signed; it read {err['CanonicalRequest']!r}"
    )
    assert err["SignatureProvided"] == dict(pairs)["X-Amz-Signature"], (
        f"the signature S3 compared against must be the untouched one from the URL "
        f"({dict(pairs)['X-Amz-Signature']!r}), got {err['SignatureProvided']!r}"
    )

    # And the original URL is unharmed -- the refusal was the tamper, not a revoked signature.
    status, _, got = _http("GET", url)
    assert status == 200, f"the untampered URL must still serve the object, got {status}"
    assert got == payload, f"untampered presigned GET served {got!r} after the tamper"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
