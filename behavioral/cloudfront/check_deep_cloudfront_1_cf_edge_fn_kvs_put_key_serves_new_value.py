"""deep-cloudfront-1-cf-edge-fn-kvs-put-key-serves-new-value."""
from __future__ import annotations

import itertools
import json
import subprocess
import time

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "deep-cloudfront-1-cf-edge-fn-kvs-put-key-serves-new-value"
GROUP = 'edge-functions'
SERVICES = ['cloudfront']


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


def _delete_kvs(cf, name):
    """ETag-guarded DeleteKeyValueStore, retried while the just-deleted function still holds it."""
    deadline = time.monotonic() + 300
    while True:
        try:
            etag = cf.describe_key_value_store(Name=name)["ETag"]
            cf.delete_key_value_store(Name=name, IfMatch=etag)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "EntityNotFound":
                return
            if code != "CannotDeleteEntityWhileInUse" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _kvs_cli(ctx, *args):
    """The cloudfront-keyvaluestore data plane through the aws CLI, which bundles the CRT SigV4A
    signer that plane requires; credentials come from ctx.subprocess_env()."""
    r = subprocess.run(["aws", "cloudfront-keyvaluestore", *args, "--region", ctx.region,
                        "--output", "json"],
                       env=ctx.subprocess_env(), capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"aws cloudfront-keyvaluestore {args[0]} failed: {r.stderr[-600:]}"
    return json.loads(r.stdout)


def _put_key(ctx, kvs_arn, key, value):
    etag = _kvs_cli(ctx, "describe-key-value-store", "--kvs-arn", kvs_arn)["ETag"]
    _kvs_cli(ctx, "put-key", "--kvs-arn", kvs_arn, "--key", key, "--value", value,
             "--if-match", etag)
    got = _kvs_cli(ctx, "get-key", "--kvs-arn", kvs_arn, "--key", key)
    assert got["Value"] == value, f"GetKey returned {got['Value']!r} right after PutKey {value!r}"


_KEY = "greeting"
# A generated viewer-request response whose body IS the value read from the store during this
# invocation; a missing key yields a sentinel rather than an exception, so "not yet visible" and
# "function broke" are distinguishable at the edge.
_FUNCTION_CODE = """
import cf from 'cloudfront';
const store = cf.kvs();
async function handler(event) {
    var value;
    try {
        value = await store.get('greeting');
    } catch (err) {
        value = 'KEY-NOT-FOUND';
    }
    return {
        statusCode: 200,
        statusDescription: 'OK',
        headers: {'x-sim2real-kvs': {value: value}, 'cache-control': {value: 'no-store'}},
        body: {encoding: 'text', data: value}
    };
}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A LIVE function reads a KeyValueStore key on every edge request, and after a PutKey of a new
    value the edge serves it without republishing the function or touching the distribution.
    """
    require_tools("aws")
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    first = ctx.unique_name("one-")
    second = ctx.unique_name("two-")

    kvs_name = ctx.unique_name("sim2real-cfedge-kvs-")
    kvs_arn = cf.create_key_value_store(Name=kvs_name, Comment="sim2real cf-edge-fn kvs")[
        "KeyValueStore"]["ARN"]
    ctx.on_cleanup(lambda: _delete_kvs(cf, kvs_name))
    _poll_until(lambda: cf.describe_key_value_store(Name=kvs_name)["KeyValueStore"]["Status"],
                lambda s: s == "READY", timeout_s=300, interval_s=5,
                description=f"key-value store {kvs_name} to reach READY")
    _put_key(ctx, kvs_arn, _KEY, first)

    # The origin is never reached (the function answers), but a distribution needs one.
    bucket = _make_bucket(ctx, s3, {"index.txt": (b"sim2real origin - never served", {})})
    oac_id = _make_oac(ctx, cf)
    fn_name, fn_arn = _make_function(ctx, cf, _FUNCTION_CODE, "sim2real kvs live read",
                                     kvs_arn=kvs_arn)

    dist_id, domain = _create_distribution(
        ctx, cf, s3, bucket, oac_id,
        _behavior([{"FunctionARN": fn_arn, "EventType": "viewer-request"}]))
    _wait_deployed(cf, dist_id)
    edge, route = ctx.endpoint_route(domain)
    url = f"{edge}/index.txt"

    before = _edge_get(url, lambda r: r.status_code == 200 and r.text == first,
                       f"the edge to serve the stored value {first!r}", headers=route)
    assert before.text == first, f"edge served {before.text!r}, the store holds {first!r}"
    assert before.headers.get("x-sim2real-kvs") == first, (
        f"x-sim2real-kvs was {before.headers.get('x-sim2real-kvs')!r}, expected {first!r}")

    _put_key(ctx, kvs_arn, _KEY, second)

    after = _edge_get(url, lambda r: r.status_code == 200 and r.text == second,
                      f"the edge to serve the updated value {second!r}", headers=route, timeout_s=300)
    assert after.text == second, f"edge served {after.text!r} after PutKey {second!r}"
    assert after.headers.get("x-sim2real-kvs") == second, (
        f"x-sim2real-kvs was {after.headers.get('x-sim2real-kvs')!r} after PutKey "
        f"{second!r}")
    assert after.text != first, "the edge still served the pre-update value"

    # Nothing but the store changed: the function is still on its first published version.
    live = cf.describe_function(Name=fn_name, Stage="LIVE")["FunctionSummary"]
    assert live["FunctionMetadata"]["FunctionARN"] == fn_arn, (
        f"the LIVE function ARN moved to {live['FunctionMetadata']['FunctionARN']!r}")
    _teardown_now("distribution", lambda: _delete_distribution(cf, dist_id))
    _teardown_now("function", lambda: _delete_function(cf, fn_name))
    _teardown_now("kvs", lambda: _delete_kvs(cf, kvs_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
