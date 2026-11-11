"""deep-cloudfront-3-cf-origin-cache-hit-leaves-origin-invocation-count-unchanged."""
from __future__ import annotations

import io
import json
import time
import urllib.parse
import zipfile

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudfront-3-cf-origin-cache-hit-leaves-origin-invocation-count-unchanged"
GROUP = "cache-key"
SERVICES = ["cloudfront", "dynamodb", "lambda"]

#: Marks a failure where the endpoint serves no edge at all, so it reads as a fidelity failure
#: rather than an environment error.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: MinTTL == DefaultTTL == MaxTTL, an hour: nothing under test can expire inside the check, so a
#: Miss must mean a different cache key and never an aged-out entry.
_TTL = 3600
_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

#: The counting echo origin. Every invocation atomically bumps two DynamoDB counters — the
#: function-wide total and one per rawPath — BEFORE it answers, so by the time CloudFront has relayed
#: the response to the client the count is final and a strongly consistent read sees it. The body
#: echoes everything the origin received: path, raw query string, cookies and headers. A direct
#: `lambda.invoke` with `sim2real_warmup` proves the execution role can write the counter (IAM
#: propagation) without touching the counted keys. The role has NO logs permission, so no
#: /aws/lambda log group is ever created and none can leak.
_FUNCTION_SOURCE = '''\
import json
import os

import boto3

_DDB = boto3.client("dynamodb")


def _bump(key):
    out = _DDB.update_item(
        TableName=os.environ["COUNT_TABLE"], Key={"pk": {"S": key}},
        UpdateExpression="ADD n :one", ExpressionAttributeValues={":one": {"N": "1"}},
        ReturnValues="UPDATED_NEW")
    return int(out["Attributes"]["n"]["N"])


def handler(event, context):
    if event.get("sim2real_warmup"):
        return {"warm": _bump("warmup")}
    path = event.get("rawPath", "")
    total = _bump("total")
    per_path = _bump("path#" + path)
    body = {
        "marker": os.environ["SIM2REAL_MARKER"],
        "total": total,
        "per_path": per_path,
        "rawPath": path,
        "rawQueryString": event.get("rawQueryString"),
        "cookies": event.get("cookies"),
        "headers": event.get("headers", {}),
        "request_id": context.aws_request_id,
        "pad": "x" * 2000,
    }
    return {"statusCode": 200, "headers": {"content-type": "application/json"},
            "body": json.dumps(body)}
'''


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment."""
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete."""
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _zip_source(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buf.getvalue()


def _counting_origin(ctx, prefix: str) -> dict:
    """Table + role + echo/count function + AWS_IAM function URL + a 'lambda' OAC to sign for it."""
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    ddb = ctx.client("dynamodb")
    marker = ctx.unique_name(f"{prefix}marker-")

    table = ctx.unique_name(f"{prefix}count-")
    ddb.create_table(
        TableName=table, BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}], Tags=_TAG_SET)
    ctx.on_cleanup(lambda: ctx.client("dynamodb").delete_table(TableName=table))
    _poll_until(lambda: ddb.describe_table(TableName=table)["Table"]["TableStatus"],
                lambda s: s == "ACTIVE", timeout_s=180.0, interval_s=3.0,
                description=f"counter table {table} to become ACTIVE")
    table_arn = ddb.describe_table(TableName=table)["Table"]["TableArn"]

    role_name = ctx.unique_name(f"{prefix}role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real counting echo origin behind CloudFront", Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="count", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "dynamodb:UpdateItem", "Resource": table_arn}],
    }))
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role_policy(RoleName=role_name,
                                                                PolicyName="count"))

    function_name = ctx.unique_name(f"{prefix}fn-")

    def create_function():
        """Create the function, tolerating ONLY the IAM propagation error."""
        try:
            return lam.create_function(
                FunctionName=function_name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": _zip_source(_FUNCTION_SOURCE)},
                Timeout=10,
                Environment={"Variables": {"SIM2REAL_MARKER": marker, "COUNT_TABLE": table}},
                Tags={t["Key"]: t["Value"] for t in _TAG_SET})
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            # Lambda reports a not-yet-propagated execution role as InvalidParameterValueException.
            return None

    _poll_until(create_function, lambda r: r is not None, timeout_s=180.0, interval_s=5.0,
                description=f"CreateFunction to accept the freshly created role {role_name}")
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))
    _poll_until(lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
                lambda s: s == "Active", timeout_s=180.0, interval_s=3.0,
                description=f"function {function_name} to become Active")

    def warm():
        out = lam.invoke(FunctionName=function_name,
                         Payload=json.dumps({"sim2real_warmup": True}).encode())
        return "FunctionError" not in out

    # IAM propagation of the inline counter grant exposes no condition but its first use.
    _poll_until(warm, bool, timeout_s=180.0, interval_s=5.0,
                description="the execution role to be allowed to write the counter table")

    function_url = lam.create_function_url_config(
        FunctionName=function_name, AuthType="AWS_IAM")["FunctionUrl"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function_url_config(
        FunctionName=function_name))
    host = urllib.parse.urlparse(function_url).netloc
    assert host, f"CreateFunctionUrlConfig returned no usable host: {function_url!r}"

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name(f"{prefix}oac-"),
        "OriginAccessControlOriginType": "lambda",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))
    return {"host": host, "function": function_name, "table": table, "oac": oac_id,
            "marker": marker}


def _origin(origin: dict, origin_id: str, origin_path: str = "") -> dict:
    return {
        "Id": origin_id, "DomainName": origin["host"], "OriginPath": origin_path,
        "CustomOriginConfig": {
            "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30, "OriginKeepaliveTimeout": 5,
        },
        "OriginAccessControlId": origin["oac"],
    }


def _behavior(path_pattern, cache_policy, *, origin_request_policy=None, target="echo",
              compress=False) -> dict:
    out = {"TargetOriginId": target, "ViewerProtocolPolicy": "allow-all",
           "CachePolicyId": cache_policy, "Compress": compress}
    if path_pattern is not None:
        out["PathPattern"] = path_pattern
    if origin_request_policy is not None:
        out["OriginRequestPolicyId"] = origin_request_policy
    return out


def _cache_policy(ctx, prefix, *, query=None, headers=None, cookies=None, gzip=False,
                  brotli=False) -> str:
    cf = ctx.client("cloudfront")
    policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name(f"{prefix}cp-"),
        "Comment": "sim2real counting-origin cache policy",
        "MinTTL": _TTL, "DefaultTTL": _TTL, "MaxTTL": _TTL,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": gzip,
            "EnableAcceptEncodingBrotli": brotli,
            "HeadersConfig": headers or {"HeaderBehavior": "none"},
            "CookiesConfig": cookies or {"CookieBehavior": "none"},
            "QueryStringsConfig": query or {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy,
                                             policy_id))
    return policy_id


def _origin_request_policy(ctx, prefix, *, headers=None, cookies=None, query=None) -> str:
    cf = ctx.client("cloudfront")
    policy_id = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": ctx.unique_name(f"{prefix}orp-"),
        "Comment": "sim2real counting-origin origin request policy",
        "HeadersConfig": headers or {"HeaderBehavior": "none"},
        "CookiesConfig": cookies or {"CookieBehavior": "none"},
        "QueryStringsConfig": query or {"QueryStringBehavior": "none"},
    })["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_request_policy,
                                             cf.delete_origin_request_policy, policy_id))
    return policy_id


def _deploy(ctx, prefix, origin, origins, behaviors, default) -> str:
    """Create the distribution (tagged in the same call), grant it the function, wait Deployed."""
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    config = {
        "CallerReference": ctx.unique_name(f"{prefix}cr-"),
        "Comment": "sim2real counting echo origin",
        "Enabled": True,
        "Origins": {"Quantity": len(origins), "Items": origins},
        "DefaultCacheBehavior": default,
    }
    if behaviors:
        config["CacheBehaviors"] = {"Quantity": len(behaviors), "Items": behaviors}
    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": config, "Tags": {"Items": _TAG_SET}})["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx.client("cloudfront"), dist_id))
    # Both grants, scoped to THIS distribution: an OAC-signed function URL origin needs
    # InvokeFunctionUrl AND InvokeFunction for the cloudfront service principal.
    lam.add_permission(FunctionName=origin["function"], StatementId="sim2real-cf-url",
                       Action="lambda:InvokeFunctionUrl", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist["ARN"], FunctionUrlAuthType="AWS_IAM")
    lam.add_permission(FunctionName=origin["function"], StatementId="sim2real-cf-fn",
                       Action="lambda:InvokeFunction", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist["ARN"])
    _wait_distribution_deployed(cf, dist_id)
    return dist["DomainName"]


def _count(ctx, origin, key: str) -> int:
    """Strongly consistent read of one invocation counter (0 if the origin never saw the key)."""
    item = ctx.client("dynamodb").get_item(
        TableName=origin["table"], Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
    return int(item["n"]["N"]) if item else 0


def _get(ctx, session, url, *, headers=None):
    """One GET; returns (response, raw body bytes exactly as sent on the wire)."""
    h = {"Accept-Encoding": "identity"}
    h.update(headers or {})
    _url, _route = ctx.endpoint_route(url)
    r = session.get(_url, headers={**h, **_route}, timeout=20, stream=True)
    return r, r.raw.read(decode_content=False)


def _warm_edge(ctx, session, domain, path="/sim2real-warmup"):
    """GET a throwaway path until the edge answers 200 from the origin (propagation)."""
    last = {}

    def probe():
        try:
            r, _ = _get(ctx, session, f"{domain}{path}")
            last["v"] = r.status_code
            return r.status_code
        except requests.RequestException as exc:  # transport only, during edge propagation
            last["v"] = repr(exc)
            return None

    try:
        _poll_until(probe, lambda s: s == 200, timeout_s=240.0, interval_s=5.0,
                    description=f"200 from https://{domain}{path}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc} (last {last.get('v')!r})") from exc


def _echo(r, raw) -> dict:
    assert r.status_code == 200, f"expected 200 from the origin, got {r.status_code}: {raw[:300]!r}"
    return json.loads(raw)


@tags("axis:happy-path", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data", "cap:c3")
def run(ctx) -> None:
    """A Hit leaves the origin's own DynamoDB invocation count EXACTLY where it was (even when a
    forwarded-only header changes), while a new cache key advances it by one, so a target cannot
    stamp 'Hit from cloudfront' yet re-fetch from the origin.
    """
    try:
        _scenario(ctx)
    finally:
        # The engine bounds ctx.run_cleanups() at 60 s, and disabling a distribution then
        # deleting it takes minutes, so the LIFO teardown runs HERE, inside the check's own
        # budget, on every path.
        ctx.run_cleanups()


def _scenario(ctx) -> None:
    """The scenario proper; run() owns the teardown."""
    prefix = "sim2real-xsvc-cfocnt-"
    origin = _counting_origin(ctx, prefix)
    keyed = _cache_policy(ctx, prefix, query={
        "QueryStringBehavior": "whitelist", "QueryStrings": {"Quantity": 1, "Items": ["simkey"]}})
    orp = _origin_request_policy(ctx, prefix, headers={
        "HeaderBehavior": "whitelist", "Headers": {"Quantity": 1, "Items": ["X-Sim-Fwd"]}})
    domain = _deploy(ctx, prefix, origin, [_origin(origin, "echo")],
                     [_behavior("/k/*", keyed, origin_request_policy=orp)],
                     _behavior(None, keyed))
    session = requests.Session()
    _warm_edge(ctx, session, domain)
    url = f"{domain}/k/obj"
    total_before = _count(ctx, origin, "total")

    r1, raw1 = _get(ctx, session, f"{url}?simkey=1", headers={"X-Sim-Fwd": "one"})
    first = _echo(r1, raw1)
    assert r1.headers.get("X-Cache") == "Miss from cloudfront", (
        f"the first request must Miss, got {r1.headers.get('X-Cache')!r}")
    assert (first["per_path"], _count(ctx, origin, "path#/k/obj")) == (1, 1), (
        f"a cold Miss must be the origin's first invocation: body said {first['per_path']!r}, "
        f"counter read {_count(ctx, origin, 'path#/k/obj')!r}")

    r2, _ = _get(ctx, session, f"{url}?simkey=1", headers={"X-Sim-Fwd": "one"})
    assert r2.headers.get("X-Cache") == "Hit from cloudfront", (
        f"an identical repeat must Hit, got {r2.headers.get('X-Cache')!r}")
    after_hit = _count(ctx, origin, "path#/k/obj")
    assert after_hit == 1, (
        f"the repeat reported X-Cache Hit, so the origin must NOT have been re-fetched: the "
        f"invocation count must still be exactly 1, it is {after_hit}")

    r3, _ = _get(ctx, session, f"{url}?simkey=1", headers={"X-Sim-Fwd": "two"})
    assert r3.headers.get("X-Cache") == "Hit from cloudfront", (
        f"X-Sim-Fwd is forwarded but not keyed, so changing it must Hit, got "
        f"{r3.headers.get('X-Cache')!r}")
    assert _count(ctx, origin, "path#/k/obj") == 1, (
        f"a forwarded-only change must not re-fetch: count {_count(ctx, origin, 'path#/k/obj')}")

    r4, raw4 = _get(ctx, session, f"{url}?simkey=2", headers={"X-Sim-Fwd": "one"})
    assert r4.headers.get("X-Cache") == "Miss from cloudfront", (
        f"simkey IS in the cache key, so a new value must Miss, got {r4.headers.get('X-Cache')!r}")
    fourth = _echo(r4, raw4)
    after_miss = _count(ctx, origin, "path#/k/obj")
    assert (after_miss, fourth["per_path"], fourth["rawQueryString"]) == (2, 2, "simkey=2"), (
        f"a request differing IN the cache key must advance the origin count to exactly 2 and "
        f"carry the new key: (counter, body per_path, rawQueryString) = "
        f"{(after_miss, fourth['per_path'], fourth['rawQueryString'])!r}")

    r5, _ = _get(ctx, session, f"{url}?simkey=2", headers={"X-Sim-Fwd": "one"})
    assert r5.headers.get("X-Cache") == "Hit from cloudfront", (
        f"the repeat of the second key must Hit, got {r5.headers.get('X-Cache')!r}")
    final = (_count(ctx, origin, "path#/k/obj"), _count(ctx, origin, "total") - total_before)
    assert final == (2, 2), (
        f"five requests, two cache keys: the origin must have run exactly twice for the path and "
        f"twice in total; (per-path, total delta) = {final!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
