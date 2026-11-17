"""apigateway-lambda-origin-cache-key-query-string-tracks-age-and-ttl-expiry."""
from __future__ import annotations

import io
import json
import ssl
import time
import urllib.error
import urllib.request
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "apigateway-lambda-origin-cache-key-query-string-tracks-age-and-ttl-expiry"
GROUP = "cache-key"
SERVICES = ["apigateway", "cloudfront", "iam", "lambda"]

#: The Lambda proxy origin. Every invocation answers its own ``aws_request_id``, which no other
#: invocation shares in any execution environment, so a cache Hit is proven by a body carrying
#: the Miss's request id and a fresh origin fetch by a new one, not by the ``X-Cache`` header alone.
_FUNCTION_SOURCE = """\
import json


def handler(event, context):
    qs = event.get("queryStringParameters") or {}
    body = json.dumps({"request_id": context.aws_request_id, "v": qs.get("v")})
    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json", "Cache-Control": "max-age=60"},
        "body": body,
    }
"""


def _zip_of(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buf.getvalue()


def _https_context(verify) -> ssl.SSLContext:
    """The TLS context http.client builds by default, verifying with ``ctx.http_verify``."""
    if verify is False:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=verify if isinstance(verify, str) and verify else None)
    context.set_alpn_protocols(["http/1.1"])
    if context.post_handshake_auth is not None:
        context.post_handshake_auth = True
    return context


def _get(url: str, *, verify, headers=None) -> tuple[int | None, dict, str]:
    """One GET; a transport error (DNS, connect, TLS, timeout) is returned as status ``None`` with
    its text, so a poll retries it instead of failing on a not-yet-propagated edge."""
    req = urllib.request.Request(url, method="GET", headers=dict(headers or {}))
    try:
        with urllib.request.urlopen(req, timeout=20, context=_https_context(verify)) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.status, headers, resp.read().decode()
    except urllib.error.HTTPError as exc:
        headers = {k.lower(): v for k, v in (exc.headers or {}).items()}
        return exc.code, headers, exc.read().decode()
    except OSError as exc:  # urllib.error.URLError, socket and TLS errors are all OSError
        return None, {}, repr(exc)


def _poll_for(fetch, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Retries ``fetch()`` until ``predicate`` accepts its result; raises, naming the last one."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fetch()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description}; last observation was {last!r}")


def _answered(result) -> bool:
    """Any HTTP answer at all: a transport error (status ``None``) is retried."""
    return result[0] is not None


def _create_execution_role(ctx) -> str:
    """A role Lambda may assume with no attached permissions: the handler calls no AWS API."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-cfagw-exec-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return role["Role"]["Arn"]


def _create_counting_function(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfagw-fn-")

    def create():
        try:
            return lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip_of(_FUNCTION_SOURCE)}, Timeout=10,
            )
        except ClientError as exc:
            # The execution role's trust policy has not yet propagated to Lambda.
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            return None

    created = _poll_for(create, lambda r: r is not None, timeout_s=90.0, interval_s=5.0,
                         description="CreateFunction to accept the freshly created role")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))

    def state():
        return lam.get_function_configuration(FunctionName=name)["State"]

    _poll_for(state, lambda s: s == "Active", timeout_s=90.0, interval_s=3.0,
              description=f"function {name} to become Active")
    return created["FunctionArn"], name


def _require_api_key(ctx, apigw, api_id: str, stage: str) -> str:
    """An enabled API key in a usage plan covering ``stage``: the method requires it, so the
    stage answers 403 to any caller but the distribution, whose origin custom header carries the
    returned key value."""
    plan_id = apigw.create_usage_plan(
        name=ctx.unique_name("sim2real-cfagw-plan-"),
        apiStages=[{"apiId": api_id, "stage": stage}],
        throttle={"rateLimit": 10.0, "burstLimit": 5},
    )["id"]
    ctx.on_cleanup(lambda: _delete_usage_plan(apigw, plan_id, api_id, stage))
    key = apigw.create_api_key(name=ctx.unique_name("sim2real-cfagw-key-"), enabled=True)
    ctx.on_cleanup(lambda: apigw.delete_api_key(apiKey=key["id"]))
    apigw.create_usage_plan_key(usagePlanId=plan_id, keyId=key["id"], keyType="API_KEY")
    ctx.on_cleanup(lambda: apigw.delete_usage_plan_key(usagePlanId=plan_id, keyId=key["id"]))
    return key["value"]


def _delete_usage_plan(apigw, plan_id: str, api_id: str, stage: str) -> None:
    """A usage plan with an associated API stage cannot be deleted; detach it, then delete."""
    try:
        apigw.update_usage_plan(
            usagePlanId=plan_id,
            patchOperations=[{"op": "remove", "path": "/apiStages", "value": f"{api_id}:{stage}"}],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise
    apigw.delete_usage_plan(usagePlanId=plan_id)


def _build_proxy_api(ctx, function_arn: str, function_name: str) -> dict:
    apigw = ctx.client("apigateway")
    lam = ctx.client("lambda")
    partition = function_arn.split(":")[1]
    api_name = ctx.unique_name("sim2real-cfagw-api-")
    api_id = apigw.create_rest_api(name=api_name, endpointConfiguration={"types": ["REGIONAL"]})["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))

    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    resource_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="count")["id"]
    apigw.put_method(restApiId=api_id, resourceId=resource_id, httpMethod="GET",
                     authorizationType="NONE", apiKeyRequired=True)
    apigw.put_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod="GET", type="AWS_PROXY",
        integrationHttpMethod="POST",
        uri=f"arn:{partition}:apigateway:{ctx.region}:lambda:path/2015-03-31/functions/{function_arn}/invocations",
    )
    lam.add_permission(
        FunctionName=function_name, StatementId=ctx.unique_name("invoke-"),
        Action="lambda:InvokeFunction", Principal="apigateway.amazonaws.com",
        SourceArn=f"arn:{partition}:execute-api:{ctx.region}:{ctx.account}:{api_id}/*/GET/count",
    )
    stage = "live"
    apigw.create_deployment(restApiId=api_id, stageName=stage)
    return {"domain": f"{api_id}.execute-api.{ctx.region}.amazonaws.com", "origin_path": f"/{stage}",
            "api_id": api_id, "stage": stage, "api_key": _require_api_key(ctx, apigw, api_id, stage)}


def _include_listed_behavior(cf) -> str:
    """The QueryStringBehavior value that keys the cache on the listed query strings only.

    It is the one enum member that is neither none, all nor allExcept, read from the client's model.
    """
    enum = cf.meta.service_model.shape_for("CachePolicyQueryStringBehavior").enum
    (value,) = [v for v in enum if v not in ("none", "all", "allExcept")]
    return value


def _create_query_string_cache_policy(ctx) -> str:
    cf = ctx.client("cloudfront")
    policy = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-cfagw-cp-"),
        "MinTTL": 0,
        "DefaultTTL": 60,
        "MaxTTL": 120,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {
                "QueryStringBehavior": _include_listed_behavior(cf),
                "QueryStrings": {"Quantity": 1, "Items": ["v"]},
            },
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_cache_policy(
        Id=policy, IfMatch=cf.get_cache_policy(Id=policy)["ETag"]))
    return policy


def _create_distribution(ctx, origin: dict, cache_policy_id: str) -> dict:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-cfagw-dist-")
    origin_id = "apigw-origin"
    config = {
        "CallerReference": ref,
        "Comment": ref,
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": origin_id,
            "DomainName": origin["domain"],
            "OriginPath": origin["origin_path"],
            "CustomHeaders": {"Quantity": 1, "Items": [
                {"HeaderName": "x-api-key", "HeaderValue": origin["api_key"]}]},
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                "OriginReadTimeout": 30,
                "OriginKeepaliveTimeout": 5,
            },
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "https-only",
            "AllowedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"],
                               "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}},
            "CachePolicyId": cache_policy_id,
            "Compress": False,
        },
    }
    created = cf.create_distribution(DistributionConfig=config)["Distribution"]
    dist_id = created["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    return {"id": dist_id, "domain": created["DomainName"]}


def _wait_deployed(cf, dist_id: str, *, timeout_s: float = 1200.0, interval_s: float = 15.0) -> None:
    def status():
        return cf.get_distribution(Id=dist_id)["Distribution"]["Status"]

    _poll_for(status, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
              description=f"distribution {dist_id} to reach Deployed")


def _disable_and_delete_distribution(cf, dist_id: str) -> None:
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg, etag = cfg_resp["DistributionConfig"], cfg_resp["ETag"]
    if cfg["Enabled"]:
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
    _wait_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Expiration.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A cache policy keyed on the ``v`` query string separates cache entries for a key-gated API
    Gateway Lambda-proxy origin: a Hit returns the Miss's own body with a growing Age, a new ``v``
    is a fresh Miss, and the origin's 60 s max-age makes the same request Miss once it elapses.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/understanding-the-cache-key.html
    """
    role_arn = _create_execution_role(ctx)
    function_arn, function_name = _create_counting_function(ctx, role_arn)
    origin = _build_proxy_api(ctx, function_arn, function_name)
    cache_policy_id = _create_query_string_cache_policy(ctx)
    dist = _create_distribution(ctx, origin, cache_policy_id)

    cf = ctx.client("cloudfront")
    _wait_deployed(cf, dist["id"])
    base, route = ctx.endpoint_route(dist["domain"])

    # The stage itself serves nobody but the distribution: a direct request without the key is
    # refused before the integration ever invokes the function.
    direct_url = f"{ctx.rest_api_url(origin['api_id'], origin['stage'])}/count"
    direct = _poll_for(lambda: _get(direct_url, verify=ctx.http_verify), _answered, timeout_s=60.0,
                       interval_s=5.0, description="any HTTP answer from the stage itself")
    assert (direct[0], json.loads(direct[2])) == (403, {"message": "Forbidden"}), (
        f"a direct request carrying no API key must be refused with 403 Forbidden, got {direct!r}"
    )

    v1 = ctx.unique_name("v1-")

    def fetch(v: str):
        return _get(f"{base}/count?v={v}", verify=ctx.http_verify, headers=route)

    status, headers, body = _poll_for(lambda: fetch(v1), lambda r: r[0] == 200, timeout_s=240.0,
                                       interval_s=10.0, description="the first request to succeed")
    assert status == 200, f"expected 200 on the first request, got {status}"
    assert headers["x-cache"] == "Miss from cloudfront", (
        f"a cache key requested for the first time ever must Miss, got {headers['x-cache']!r}"
    )
    first_body = json.loads(body)
    assert first_body["v"] == v1, f"the origin must echo the requested v={v1!r}, got {first_body!r}"
    first_request_id = first_body["request_id"]
    assert isinstance(first_request_id, str) and first_request_id, (
        f"the origin must answer its invocation's request id, got {first_body!r}"
    )

    def hit_with_age(min_age: int):
        def attempt():
            status, headers, body = fetch(v1)
            return status, headers, body

        def accepted(result):
            # Anycast can send a repeat request to another edge location, which caches its own
            # origin answer; only a Hit of the object the first Miss cached is the one graded.
            status, headers, body = result
            if status != 200 or headers.get("x-cache") != "Hit from cloudfront":
                return False
            try:
                same_object = json.loads(body) == first_body
            except ValueError:
                return False
            return same_object and int(headers.get("age", -1)) >= min_age

        return _poll_for(attempt, accepted, timeout_s=90.0, interval_s=2.0,
                          description=f"a Hit of the first Miss's object with Age >= {min_age}")

    _, headers, _ = hit_with_age(1)
    age_at_first_hit = int(headers["age"])

    _, headers, _ = hit_with_age(age_at_first_hit + 1)
    age_at_second_hit = int(headers["age"])
    assert age_at_second_hit > age_at_first_hit, (
        f"Age must grow between two Hits on the same cached object: {age_at_first_hit} then "
        f"{age_at_second_hit}"
    )

    v2 = ctx.unique_name("v2-")
    status, headers, body = _poll_for(lambda: fetch(v2), lambda r: r[0] == 200, timeout_s=90.0,
                                       interval_s=5.0, description="the differently-keyed request")
    assert headers["x-cache"] == "Miss from cloudfront", (
        f"a distinct 'v' value is a distinct cache key and must Miss, got {headers['x-cache']!r}"
    )
    second_key_body = json.loads(body)
    assert second_key_body["v"] == v2, (
        f"the origin must echo the requested v={v2!r}, got {second_key_body!r}"
    )
    assert second_key_body["request_id"] != first_request_id, (
        f"a new cache key's Miss must be a fresh origin invocation, yet it answered the first "
        f"request's id {first_request_id!r}"
    )

    # The origin's Cache-Control: max-age=60 is an AWS-defined period CloudFront holds the object
    # for; only after it elapses does the same request Miss again.
    deadline = time.monotonic() + 65.0
    while time.monotonic() < deadline:
        time.sleep(5.0)

    status, headers, body = _poll_for(lambda: fetch(v1), lambda r: r[0] == 200, timeout_s=90.0,
                                       interval_s=5.0, description="v1 after its max-age elapsed")
    assert headers["x-cache"] == "Miss from cloudfront", (
        f"once max-age=60 has elapsed the same request must Miss again, got {headers['x-cache']!r}"
    )
    expired_body = json.loads(body)
    assert expired_body["v"] == v1, f"the origin must echo the requested v={v1!r}, got {expired_body!r}"
    seen = {first_request_id, second_key_body["request_id"]}
    assert expired_body["request_id"] not in seen, (
        f"the expiry Miss must be a fresh origin invocation, yet it answered an earlier request's "
        f"id {expired_body['request_id']!r} (earlier: {sorted(seen)!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
