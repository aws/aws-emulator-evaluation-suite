"""sigv4skew-future-dated-put-outside-window-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sigv4skew-future-dated-put-outside-window-rejected"
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
    if location != "us-east-1":  # CreateBucket's own region-pinned default; S3 rejects an explicit LocationConstraint for it
        params["CreateBucketConfiguration"] = {"LocationConstraint": location}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _ssl_context(verify):
    """An SSL context honoring ``ctx.http_verify``: default, a CA bundle path, or unverified."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    return None


def _http(method, url, verify, headers=None, data=None):
    """Raw HTTP request; returns (status, lowercased-headers, body-bytes). 4xx/5xx captured."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, method=method, data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ssl_context(verify)) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        body = exc.read() if hasattr(exc, "read") else b""
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, body


def _error_code(fn):
    """The AWS (code, message) ``fn`` raised; an unexpected success raises instead of returning.
    Accepting input real AWS refuses must fail loudly, not read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("the call SUCCEEDED where real AWS raises an error")


def _error_xml(body):
    """Parse an S3 REST error body structurally into {element-tag: text}."""
    from xml.etree import ElementTree

    root = ElementTree.fromstring(body)
    assert root.tag == "Error", f"expected an <Error> document, got <{root.tag}>: {body[:200]!r}"
    return {child.tag: (child.text or "") for child in root}


def _server_now(client, bucket):
    """S3's own current UTC instant, read from the Date response header.
    Offsets are measured against S3's clock so local clock drift cannot blur the skew window."""
    import email.utils

    headers = client.head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPHeaders"]
    date = headers.get("date")
    assert date, f"S3 returned no Date header to read its clock from; headers were {sorted(headers)!r}"
    return email.utils.parsedate_to_datetime(date).replace(tzinfo=None)


def _signing_creds(ctx, client=None):
    """The S3 client's own signing credentials, as raw key material for hand-signing.
    Read from the client's signer rather than the ambient credential chain."""
    signer = (client or ctx.client("s3"))._request_signer._credentials
    assert signer is not None, "the S3 client carries no credentials; the harness must supply credentials"
    frozen = signer.get_frozen_credentials()
    return {"access_key": frozen.access_key, "secret_key": frozen.secret_key, "token": frozen.token}


def _sigv4_headers(creds, region, method, host, path, payload, when, extra=None):
    """SigV4-sign an S3 REST request at an EXPLICIT instant; returns the headers to send.
    Hand-rolled: botocore's SigV4Auth reads the clock itself and cannot sign a skewed date."""
    import hashlib
    import hmac
    import urllib.parse

    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    datestamp = amz_date[:8]
    payload_hash = hashlib.sha256(payload).hexdigest()
    headers = {"host": host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
    if creds.get("token"):
        headers["x-amz-security-token"] = creds["token"]
    headers.update({k.lower(): v for k, v in (extra or {}).items()})
    names = sorted(headers)
    canonical_headers = "".join(f"{n}:{headers[n].strip()}\n" for n in names)
    signed_headers = ";".join(names)
    canonical_request = "\n".join(
        [
            method,
            urllib.parse.quote(path, safe="/~"),
            "",
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{datestamp}/{region}/s3/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )
    key = ("AWS4" + creds["secret_key"]).encode()
    for part in (datestamp, region, "s3", "aws4_request"):
        key = hmac.new(key, part.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={creds['access_key']}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return headers


def _target(client, bucket, key):
    """(url, host, path) for a raw path-style request at ``key`` in ``bucket`` on ``client``'s
    endpoint; ``host`` is the endpoint's host, which the request carries and signs."""
    from urllib.parse import urlsplit

    base = client.meta.endpoint_url.rstrip("/")
    path = f"/{bucket}/{key}"
    return f"{base}{path}", urlsplit(base).netloc, path


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A PutObject signed 1500 s ahead of S3's clock is refused RequestTimeTooSkewed, no write,
    while one signed 240 s ahead, inside the reported window, succeeds.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    creds = _signing_creds(ctx)
    payload = b"sigv4skew-future-dated-payload"
    skewed_key, control_key = "sigv4skew/skewed.txt", "sigv4skew/control.txt"

    # Break exactly one thing: the X-Amz-Date, 1500 s AHEAD of the target's own clock.
    skewed_at = _server_now(s3, bucket) + datetime.timedelta(seconds=1500)
    url, host, path = _target(s3, bucket, skewed_key)
    status, _, body = _http(
        "PUT", url, ctx.http_verify,
        _sigv4_headers(creds, ctx.region, "PUT", host, path, payload, skewed_at), payload
    )
    assert status == 403, (
        f"a PUT signed 1500 s ahead of S3's clock must be refused 403, got {status}: {body[:300]!r}"
    )
    err = _error_xml(body)
    assert err["Code"] == "RequestTimeTooSkewed", (
        f"expected RequestTimeTooSkewed for a future-dated signature, got {err['Code']!r} "
        f"({err.get('Message')!r})"
    )
    assert err["Message"] == (
        "The difference between the request time and the current time is too large."
    ), (
        f"unexpected RequestTimeTooSkewed message {err['Message']!r}"
    )
    assert err["RequestTime"] == skewed_at.strftime("%Y%m%dT%H%M%SZ"), (
        f"the refusal must echo the future X-Amz-Date we signed "
        f"({skewed_at.strftime('%Y%m%dT%H%M%SZ')!r}), got {err['RequestTime']!r}"
    )
    server_time = err["ServerTime"]
    assert server_time and server_time < skewed_at.strftime("%Y-%m-%dT%H:%M:%SZ"), (
        f"a future-dated refusal must report a ServerTime BEFORE the request time; got "
        f"ServerTime={server_time!r} against RequestTime={err['RequestTime']!r}"
    )
    window_ms = int(err["MaxAllowedSkewMilliseconds"])
    assert 0 < window_ms < 1500 * 1000, (
        f"S3 reported a tolerance of {window_ms} ms; for this to be a skew rejection at all the "
        f"1500000 ms offset we signed has to fall outside it"
    )

    # Effect absent: the refused request wrote nothing, so the key does not exist.
    code, message = _error_code(lambda: s3.get_object(Bucket=bucket, Key=skewed_key))
    assert code == "NoSuchKey", (
        f"the future-dated PUT must not have written {skewed_key!r}; get_object answered {code!r}"
    )
    assert message == "The specified key does not exist.", (
        f"get_object of the absent key must say 'The specified key does not exist.', got {message!r}"
    )

    # Positive control: 240 s AHEAD is still inside the window S3 just reported.
    inside_at = _server_now(s3, bucket) + datetime.timedelta(seconds=240)
    assert 240 * 1000 < window_ms, (
        f"the control offset 240000 ms must be inside the {window_ms} ms window S3 reported"
    )
    url, host, path = _target(s3, bucket, control_key)
    status, _, body = _http(
        "PUT", url, ctx.http_verify,
        _sigv4_headers(creds, ctx.region, "PUT", host, path, payload, inside_at), payload
    )
    assert status == 200, (
        f"a PUT signed 240 s ahead of S3's clock is inside its window and must succeed, got "
        f"{status}: {body[:300]!r}"
    )
    url, host, path = _target(s3, bucket, control_key)
    status, _, got = _http(
        "GET", url, ctx.http_verify,
        _sigv4_headers(creds, ctx.region, "GET", host, path, b"", _server_now(s3, bucket))
    )
    assert status == 200, f"signed GET of the control object returned {status}: {got[:300]!r}"
    assert got == payload, f"control object served {got!r}, expected the bytes we wrote {payload!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
