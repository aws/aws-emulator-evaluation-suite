"""error-caching-min-ttl-holds-a-plain-502-but-not-a-no-store-502."""
from __future__ import annotations

import io
import json
import time
import urllib.parse
import zipfile

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-caching-min-ttl-holds-a-plain-502-but-not-a-no-store-502"
GROUP = "caching"
SERVICES = ["cloudfront", "iam", "lambda", "logs"]

#: Marks a failure caused by an edge data plane that serves no traffic at all.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: The Error Caching Minimum TTL this check configures on its one CustomErrorResponse entry.
_ERROR_CACHING_MIN_TTL = 10

#: The origin request policy CloudFront documents for a Lambda function URL origin: forwarding the
#: viewer's Host header would break the sigv4 signature the OAC computes.
_ALL_VIEWER_EXCEPT_HOST = "Managed-AllViewerExceptHostHeader"

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

#: Each response carries a fresh nonce, so a repeat with the SAME body proves CloudFront answered
#: from its cache instead of invoking the origin again.
_FUNCTION_SOURCE = '''\
import uuid


def handler(event, context):
    nonce = uuid.uuid4().hex
    path = event.get("rawPath", "/")
    headers = {"Content-Type": "text/plain"}
    if path == "/ok":
        status = 200
    elif path == "/err-502-plain":
        status = 502
    elif path == "/err-502-no-store":
        status = 502
        headers["Cache-Control"] = "no-store"
    else:
        status = 404
    return {
        "statusCode": status,
        "headers": headers,
        "body": f"{status}-{nonce}",
    }
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


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean "
                    f"reads"
                )
            time.sleep(interval_s)


def _managed_origin_request_policy_id(cf, name: str) -> str:
    """Resolve a managed origin request policy id by name from the target's own catalogue."""
    marker = None
    while True:
        kwargs = {"Type": "managed", "MaxItems": "100"}
        if marker is not None:
            kwargs["Marker"] = marker
        page = cf.list_origin_request_policies(**kwargs)["OriginRequestPolicyList"]
        for item in page["Items"]:
            if item["OriginRequestPolicy"]["OriginRequestPolicyConfig"]["Name"] == name:
                return item["OriginRequestPolicy"]["Id"]
        marker = page.get("NextMarker")
        if marker is None:
            raise AssertionError(
                f"the managed origin request policy {name!r} is required for a Lambda function URL "
                f"origin and the target's managed catalogue does not list it"
            )


def _create_function_when_role_assumable(lam, **kwargs):
    """create_function, retrying only while Lambda refuses the fresh role as not yet assumable."""
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            return lam.create_function(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            if "cannot be assumed" not in exc.response["Error"].get("Message", ""):
                raise
            last = exc
        time.sleep(5.0)
    raise AssertionError(f"the role never became assumable by Lambda within 180s: {last}")


def _fetch_ok(session, url, *, timeout_s=240.0, interval_s=5.0):
    """GET url until it answers 200, then return that response; raise (marked) on exhaustion."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, timeout=20)
        except requests.RequestException as exc:  # transport only, during edge propagation
            last = exc
            return None
        return last

    try:
        return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


# timing:real-time — ttl: 10 s https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/custom-error-pages-expiration.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A 502 with no Cache-Control header is held for the Error Caching Minimum TTL; a 502 whose
    origin sends Cache-Control: no-store is never cached.

    Reference: https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/custom-error-pages-expiration.html
    """
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    role_name = ctx.unique_name("sim2real-behav-cferrttl-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))

    function_name = ctx.unique_name("sim2real-behav-cferrttl-fn-")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{function_name}"))

    created = _create_function_when_role_assumable(
        lam,
        FunctionName=function_name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="index.handler",
        Code={"ZipFile": _zip_source(_FUNCTION_SOURCE)},
        Timeout=10,
        Tags={t["Key"]: t["Value"] for t in _TAG_SET},
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))
    assert created["FunctionName"] == function_name, (
        f"expected the created function to be named {function_name!r}, got "
        f"{created['FunctionName']!r}"
    )
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda state: state == "Active",
        timeout_s=180.0, interval_s=5.0,
        description=f"lambda function {function_name} to become Active",
    )

    function_url = lam.create_function_url_config(
        FunctionName=function_name, AuthType="AWS_IAM")["FunctionUrl"]
    ctx.on_cleanup(lambda: lam.delete_function_url_config(FunctionName=function_name))
    origin_host = urllib.parse.urlparse(function_url).netloc
    assert origin_host != "", (
        f"CreateFunctionUrlConfig must return an absolute https URL to use as an origin domain, "
        f"got {function_url!r}"
    )

    cache_policy_id = cf.create_cache_policy(CachePolicyConfig={
        "Name": ctx.unique_name("sim2real-behav-cferrttl-cp-"),
        "Comment": "sim2real error caching min ttl",
        "MinTTL": 0,
        "DefaultTTL": 0,
        "MaxTTL": 30,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    })["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy,
                                             cache_policy_id))

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cferrttl-oac-"),
        "OriginAccessControlOriginType": "lambda",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    orp_id = _managed_origin_request_policy_id(cf, _ALL_VIEWER_EXCEPT_HOST)

    dist = cf.create_distribution(DistributionConfig={
        "CallerReference": ctx.unique_name("sim2real-behav-cferrttl-cr-"),
        "Comment": "sim2real error caching min ttl vs origin no-store",
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "lambdaurl",
            "DomainName": origin_host,
            "CustomOriginConfig": {
                "HTTPPort": 80,
                "HTTPSPort": 443,
                "OriginProtocolPolicy": "https-only",
                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                "OriginReadTimeout": 30,
                "OriginKeepaliveTimeout": 5,
            },
            "OriginAccessControlId": oac_id,
        }]},
        # No ResponsePagePath or ResponseCode: the origin's 502 status and body pass through
        # unchanged, and only the caching duration is configured.
        "CustomErrorResponses": {"Quantity": 1, "Items": [
            {"ErrorCode": 502, "ErrorCachingMinTTL": _ERROR_CACHING_MIN_TTL},
        ]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "lambdaurl",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": cache_policy_id,
            "OriginRequestPolicyId": orp_id,
        },
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    domain = dist["DomainName"]
    cf.tag_resource(Resource=dist["ARN"], Tags={"Items": _TAG_SET})

    stored_items = dist["DistributionConfig"]["CustomErrorResponses"]["Items"]
    stored_ttl = {item["ErrorCode"]: item["ErrorCachingMinTTL"] for item in stored_items}
    assert stored_ttl == {502: _ERROR_CACHING_MIN_TTL}, (
        f"expected the configured Error Caching Minimum TTL to round-trip unchanged, got "
        f"{stored_ttl!r}"
    )

    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-allow-cloudfront-oac-url",
        Action="lambda:InvokeFunctionUrl",
        Principal="cloudfront.amazonaws.com",
        SourceArn=dist["ARN"],
        FunctionUrlAuthType="AWS_IAM",
    )
    ctx.on_cleanup(lambda: lam.remove_permission(
        FunctionName=function_name, StatementId="sim2real-allow-cloudfront-oac-url"))
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-allow-cloudfront-oac-fn",
        Action="lambda:InvokeFunction",
        Principal="cloudfront.amazonaws.com",
        SourceArn=dist["ARN"],
    )
    ctx.on_cleanup(lambda: lam.remove_permission(
        FunctionName=function_name, StatementId="sim2real-allow-cloudfront-oac-fn"))

    _wait_distribution_deployed(cf, dist_id)

    session = requests.Session()
    edge, route = ctx.endpoint_route(domain)
    session.headers.update(route)

    ok = _fetch_ok(session, f"{edge}/ok")
    assert ok.content.decode().split("-", 1)[0] == "200", (
        f"the reachability control must serve the origin's own body, got {ok.content[:120]!r}"
    )

    cold_plain = session.get(f"{edge}/err-502-plain", timeout=20)
    assert cold_plain.status_code == 502, (
        f"expected the origin's 502 to reach the viewer, got {cold_plain.status_code}"
    )
    assert cold_plain.content.decode().split("-", 1)[0] == "502", (
        f"expected the origin's own 502 body, got {cold_plain.content[:120]!r} — a differently "
        f"shaped body means CloudFront, not the origin, generated this error"
    )
    stored_at = time.monotonic()
    warm_plain = session.get(f"{edge}/err-502-plain", timeout=20)
    assert warm_plain.status_code == 502, (
        f"expected the cached 502 on an immediate repeat, got {warm_plain.status_code}"
    )
    assert warm_plain.content == cold_plain.content, (
        f"an immediate repeat returned a different body ({warm_plain.content!r} vs "
        f"{cold_plain.content!r}) — the origin was re-invoked despite sending no Cache-Control "
        f"header, which the configured Error Caching Minimum TTL should still hold"
    )

    cold_nostore = session.get(f"{edge}/err-502-no-store", timeout=20)
    assert cold_nostore.status_code == 502, (
        f"expected the origin's 502 to reach the viewer, got {cold_nostore.status_code}"
    )
    assert cold_nostore.content.decode().split("-", 1)[0] == "502", (
        f"expected the origin's own 502 body, got {cold_nostore.content[:120]!r}"
    )
    warm_nostore = session.get(f"{edge}/err-502-no-store", timeout=20)
    assert warm_nostore.status_code == 502, (
        f"expected 502 on an immediate repeat, got {warm_nostore.status_code}"
    )
    assert warm_nostore.content.decode().split("-", 1)[0] == "502", (
        f"expected the origin's own 502 body on repeat, got {warm_nostore.content[:120]!r}"
    )
    assert warm_nostore.content != cold_nostore.content, (
        f"an immediate repeat returned the SAME body ({warm_nostore.content!r}) — a 502 whose "
        f"origin sends Cache-Control: no-store must not be cached, so each request must reach "
        f"the origin again"
    )

    expired = _poll_until(
        lambda: session.get(f"{edge}/err-502-plain", timeout=20),
        lambda r: r.status_code == 502 and r.content != warm_plain.content,
        timeout_s=90.0, interval_s=2.0,
        description=(f"the cached, header-less 502 to expire once the configured Error Caching "
                     f"Minimum TTL ({_ERROR_CACHING_MIN_TTL}s) elapses"),
    )
    elapsed = time.monotonic() - stored_at
    assert elapsed >= _ERROR_CACHING_MIN_TTL, (
        f"the cached 502 expired after {elapsed:.1f}s, earlier than its "
        f"{_ERROR_CACHING_MIN_TTL}s Error Caching Minimum TTL"
    )
    assert expired.content.decode().split("-", 1)[0] == "502", (
        f"expected a fresh 502 from the origin after expiry, got {expired.content[:120]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
