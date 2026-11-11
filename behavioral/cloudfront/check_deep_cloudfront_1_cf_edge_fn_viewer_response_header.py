"""deep-cloudfront-1-cf-edge-fn-viewer-response-header."""
from __future__ import annotations

import itertools
import json
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudfront-1-cf-edge-fn-viewer-response-header"
GROUP = 'edge-functions'
SERVICES = ['cloudfront']

# ===== helpers =====

_COUNTER = itertools.count()
# Managed "CachingDisabled": every request reaches the function AND the origin, so what is served
# is decided by this request's rewrite, never by an earlier request's cached object.
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
# Tags a Deployed distribution that never serves as a data-plane failure, so the transport error
# behind it is not read as an environment problem.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


def _error_code(fn):
    """The AWS error code fn raises. An unexpected SUCCESS raises, never returns a falsy code."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id):
    """Poll GetDistribution until Status == 'Deployed'; return the latest ETag."""
    holder = {}

    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=1200, interval_s=15,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _delete_distribution(cf, dist_id):
    """Disable, wait for the disable to deploy, delete. Idempotent: gone is done."""
    try:
        resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = resp["DistributionConfig"], resp["ETag"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_function(cf, name):
    """ETag-guarded DeleteFunction, retried while CloudFront still reports it in use by the
    distribution that was just deleted. Idempotent."""
    deadline = time.monotonic() + 300
    while True:
        try:
            etag = cf.describe_function(Name=name)["ETag"]
            cf.delete_function(Name=name, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchFunctionExists":
                return
            if code != "FunctionInUse" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _delete_oac(cf, oac_id):
    try:
        etag = cf.get_origin_access_control(Id=oac_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchOriginAccessControl":
            return
        raise
    cf.delete_origin_access_control(Id=oac_id, IfMatch=etag)


def _delete_bucket(s3, bucket):
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _teardown_now(label, fn):
    """Run a teardown inside the check body; a failure raises, naming the resource."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - re-raised with the resource named
        raise RuntimeError(f"teardown of {label} failed in-body: {exc!r}") from exc


def _make_bucket(ctx, s3, objects):
    """A private bucket in ctx.region holding ``objects`` ({key: (body, metadata)})."""
    bucket = ctx.unique_name("sim2real-cfedge-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    for key, (body, meta) in objects.items():
        s3.put_object(Bucket=bucket, Key=key, Body=body, ContentType="text/plain", Metadata=meta)
    return bucket


def _make_oac(ctx, cf):
    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-cfedge-oac-"),
        "Description": "sim2real cf-edge-fn",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(cf, oac_id))
    return oac_id


def _make_function(ctx, cf, code, comment, kvs_arn=None):
    """Create a cloudfront-js-2.0 function and publish it to LIVE. -> (name, live ARN)."""
    name = ctx.unique_name("sim2real-cfedge-fn-")
    config = {"Comment": comment, "Runtime": "cloudfront-js-2.0"}
    if kvs_arn:
        config["KeyValueStoreAssociations"] = {"Quantity": 1,
                                               "Items": [{"KeyValueStoreARN": kvs_arn}]}
    created = cf.create_function(Name=name, FunctionConfig=config, FunctionCode=code.encode())
    ctx.on_cleanup(lambda: _delete_function(cf, name))
    published = cf.publish_function(Name=name, IfMatch=created["ETag"])
    meta = published["FunctionSummary"]["FunctionMetadata"]
    assert meta["Stage"] == "LIVE", f"PublishFunction left the function in stage {meta['Stage']!r}"
    return name, meta["FunctionARN"]


def _behavior(fn_assocs, path=None):
    b = {
        "TargetOriginId": "s3-origin",
        "ViewerProtocolPolicy": "https-only",
        "CachePolicyId": CACHING_DISABLED,
        "FunctionAssociations": {"Quantity": len(fn_assocs), "Items": fn_assocs},
    }
    if path:
        b["PathPattern"] = path
    return b


def _create_distribution(ctx, cf, s3, bucket, oac_id, default, extra=()):
    """Distribution over the OAC-locked bucket. Returns (dist_id, domain).

    CallerReference starts `sim2real-cf-` so leftover distributions can be found by prefix."""
    cfg = {
        "CallerReference": f"sim2real-cf-{ctx.unique_name('edge-')}-{next(_COUNTER)}",
        "Comment": "sim2real cf-edge-fn",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "s3-origin",
            "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
            "S3OriginConfig": {"OriginAccessIdentity": ""},
            "OriginAccessControlId": oac_id,
        }]},
        "DefaultCacheBehavior": default,
    }
    if extra:
        cfg["CacheBehaviors"] = {"Quantity": len(extra), "Items": list(extra)}
    dist = cf.create_distribution(DistributionConfig=cfg)["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist["ARN"]}},
        }],
    }))
    return dist_id, dist["DomainName"]


def _edge_get(url, predicate, description, headers=None, timeout_s=240):
    """GET through the edge until predicate(response) holds. Transport errors are kept, so an
    expiry names its cause instead of `last: None`."""
    errors = []

    def fetch():
        try:
            return requests.get(url, headers=headers or {}, timeout=15)
        except requests.RequestException as exc:
            errors.append(exc)
            return None

    try:
        return _poll_until(fetch, lambda r: r is not None and predicate(r),
                           timeout_s=timeout_s, interval_s=5, description=description)
    except AssertionError as exc:
        tail = f" (last transport error: {errors[-1]!r})" if errors else ""
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}{tail}") from exc

# ===== end helpers =====

# Adds a header whose value is DERIVED from the live request (its URI), and deletes an S3
# user-metadata header the origin really sent. Neither effect is visible through any signed API.
_FUNCTION_CODE = """
function handler(event) {
    var response = event.response;
    response.headers['x-sim2real-edge'] = {value: 'stamped:' + event.request.uri};
    delete response.headers['x-amz-meta-sim2real-secret'];
    return response;
}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A LIVE viewer-response function adds one response header and strips another at the edge,
    on exactly the cache behaviour it is associated with, while origin bytes pass through intact.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    secret = ctx.unique_name("s")
    body = b"sim2real viewer-response origin object"
    bucket = _make_bucket(ctx, s3, {
        "index.txt": (body, {"sim2real-secret": secret}),
        "raw/index.txt": (body, {"sim2real-secret": secret}),
    })
    oac_id = _make_oac(ctx, cf)
    fn_name, fn_arn = _make_function(ctx, cf, _FUNCTION_CODE, "sim2real viewer-response header")

    dist_id, domain = _create_distribution(
        ctx, cf, s3, bucket, oac_id,
        _behavior([{"FunctionARN": fn_arn, "EventType": "viewer-response"}]),
        extra=[_behavior([], path="raw/*")])
    _wait_deployed(cf, dist_id)

    # Control behaviour (no function): the origin's metadata header reaches the viewer and no
    # edge header is added. This is what the function is measured against.
    edge, route = ctx.endpoint_route(domain)
    raw = _edge_get(f"{edge}/raw/index.txt", lambda r: r.status_code == 200,
                    "200 for /raw/index.txt on the function-free behaviour", headers=route)
    assert raw.content == body, f"control behaviour served {raw.content!r}, expected {body!r}"
    assert raw.headers.get("x-amz-meta-sim2real-secret") == secret, (
        f"the origin metadata header did not reach the viewer on the function-free behaviour: "
        f"{dict(raw.headers)!r}")
    assert "x-sim2real-edge" not in raw.headers, (
        f"x-sim2real-edge appeared on a behaviour with no function: {dict(raw.headers)!r}")

    # Function behaviour: header added (value derived from the request URI), header removed.
    fn = _edge_get(f"{edge}/index.txt", lambda r: r.status_code == 200,
                   "200 for /index.txt on the viewer-response behaviour", headers=route)
    assert fn.content == body, (
        f"viewer-response must not alter the body; served {fn.content!r}, expected {body!r}")
    assert fn.headers.get("x-sim2real-edge") == "stamped:/index.txt", (
        f"the edge did not add x-sim2real-edge='stamped:/index.txt'; headers were "
        f"{dict(fn.headers)!r}")
    assert "x-amz-meta-sim2real-secret" not in fn.headers, (
        f"the function deletes x-amz-meta-sim2real-secret, but the viewer still received "
        f"{fn.headers.get('x-amz-meta-sim2real-secret')!r}")

    # TestFunction on the same LIVE function describes the identical delta.
    etag = cf.describe_function(Name=fn_name, Stage="LIVE")["ETag"]
    event = json.dumps({
        "version": "1.0",
        "context": {"eventType": "viewer-response"},
        "viewer": {"ip": "203.0.113.10"},
        "request": {"method": "GET", "uri": "/index.txt", "querystring": {}, "headers": {},
                    "cookies": {}},
        "response": {"statusCode": 200, "statusDescription": "OK", "cookies": {},
                     "headers": {"x-amz-meta-sim2real-secret": {"value": secret},
                                 "content-type": {"value": "text/plain"}}},
    }).encode()
    result = cf.test_function(Name=fn_name, IfMatch=etag, Stage="LIVE",
                              EventObject=event)["TestResult"]
    assert not result.get("FunctionErrorMessage"), (
        f"TestFunction raised: {result.get('FunctionErrorMessage')!r}")
    out = json.loads(result["FunctionOutput"])
    test_headers = out.get("response", out)["headers"]
    assert test_headers.get("x-sim2real-edge") == {"value": "stamped:/index.txt"}, (
        f"TestFunction output headers {test_headers!r} disagree with the edge, which added "
        f"x-sim2real-edge='stamped:/index.txt'")
    assert "x-amz-meta-sim2real-secret" not in test_headers, (
        f"TestFunction kept the header the edge removed: {test_headers!r}")
    _teardown_now("distribution", lambda: _delete_distribution(cf, dist_id))
    _teardown_now("function", lambda: _delete_function(cf, fn_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
