"""sigv4skew-cross-region-credential-scope-rejected."""
from __future__ import annotations

import datetime

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sigv4skew-cross-region-credential-scope-rejected"
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
    # us-east-1 is CreateBucket's implicit default region; an explicit LocationConstraint for it is rejected.
    if location != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": location}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _second_region(ctx):
    """A region other than ctx.region, from the account's own enabled region list.
    Never a literal: a hardcoded region hides region-handling defects and may be disabled."""
    ec2 = ctx.client("ec2")
    enabled = {
        r["RegionName"]: r.get("OptInStatus")
        for r in ec2.describe_regions(AllRegions=False)["Regions"]
    }
    candidates = sorted(
        name
        for name, status in enabled.items()
        if name != ctx.region and status in ("opt-in-not-required", "opted-in")
    )
    assert candidates, (
        f"no enabled region other than {ctx.region!r} to sign against; describe_regions reported "
        f"{enabled!r}"
    )
    chosen = candidates[0]
    assert enabled[chosen] in ("opt-in-not-required", "opted-in"), (
        f"chose {chosen!r} but its opt-in status is {enabled[chosen]!r}, not enabled for this account"
    )
    return chosen


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A correctly-timed PUT whose credential scope names the wrong region is refused with
    AuthorizationHeaderMalformed and writes nothing; the same request scoped correctly succeeds.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
    """
    s3 = ctx.client("s3")
    creds = _signing_creds(ctx)
    region2 = _second_region(ctx)
    s3b = ctx.client("s3", region=region2)
    bucket2 = _new_bucket(ctx, s3b, region=region2)
    payload = b"sigv4skew-cross-region-scope-payload"
    key = "sigv4skew/scoped.txt"

    # Break exactly one thing: sign for ctx.region while addressing the bucket in region2.
    url, host, path = _target(s3b, bucket2, key)
    signed_at = _server_now(s3b, bucket2)
    status, _, body = _http(
        "PUT", url, ctx.http_verify,
        _sigv4_headers(creds, ctx.region, "PUT", host, path, payload, signed_at), payload
    )
    assert status == 400, (
        f"a PUT scoped to {ctx.region!r} but sent to {region2!r} must be refused 400, got {status}: "
        f"{body[:300]!r}"
    )
    err = _error_xml(body)
    assert err["Code"] == "AuthorizationHeaderMalformed", (
        f"expected AuthorizationHeaderMalformed, got {err['Code']!r} ({err.get('Message')!r})"
    )
    assert err["Region"] == region2, (
        f"the refusal must name the region it expected ({region2!r}), got {err['Region']!r}"
    )
    expected = (
        f"The authorization header is malformed; the region '{ctx.region}' is wrong; "
        f"expecting '{region2}'"
    )
    assert err["Message"] == expected, (
        f"the message must name the region we signed for and the one expected: {expected!r}; "
        f"got {err['Message']!r}"
    )

    # Effect absent: the mis-scoped request wrote nothing.
    code, message = _error_code(lambda: s3b.get_object(Bucket=bucket2, Key=key))
    assert code == "NoSuchKey", (
        f"the mis-scoped PUT must not have written {key!r}; get_object answered {code!r}"
    )
    assert message == "The specified key does not exist.", (
        f"get_object of the absent key must say 'The specified key does not exist.', got {message!r}"
    )

    # Positive control: the same request, same instant, scoped to region2, writes the bytes.
    url, host, path = _target(s3b, bucket2, key)
    status, _, body = _http(
        "PUT", url, ctx.http_verify,
        _sigv4_headers(creds, region2, "PUT", host, path, payload, signed_at), payload
    )
    assert status == 200, (
        f"the same request scoped to {region2!r} must succeed, got {status}: {body[:300]!r}"
    )
    url, host, path = _target(s3b, bucket2, key)
    status, _, got = _http(
        "GET", url, ctx.http_verify,
        _sigv4_headers(creds, region2, "GET", host, path, b"", _server_now(s3b, bucket2)),
    )
    assert status == 200, f"signed GET of the correctly-scoped object returned {status}"
    assert got == payload, f"the object served {got!r}, expected the bytes we wrote {payload!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
