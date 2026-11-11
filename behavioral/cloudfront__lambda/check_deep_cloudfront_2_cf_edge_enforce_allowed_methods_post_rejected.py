"""deep-cloudfront-2-cf-edge-enforce-allowed-methods-post-rejected."""
from __future__ import annotations

import io
import json
import time
import urllib.parse
import zipfile

import requests
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudfront-2-cf-edge-enforce-allowed-methods-post-rejected"
GROUP = "security"
SERVICES = ["cloudfront", "lambda"]

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

#: One log line per invocation is the origin's request counter.
_FUNCTION_SOURCE = '''\
import json
import os


def handler(event, context):
    method = event["requestContext"]["http"]["method"]
    query = event.get("rawQueryString", "")
    print(f"SIM2REAL_HIT {method} {query}")
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "marker": os.environ["SIM2REAL_MARKER"],
            "method": method,
            "query": query,
            "header_names": sorted(event.get("headers") or {}),
        }),
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


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=1200.0, interval_s=15.0) -> str:
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
    """Disable, wait for that change to deploy, then delete (CloudFront refuses an enabled delete).
    Called in the body on the success path and registered as the ctx.on_cleanup net for a
    failing run; a no-op once the distribution is gone.
    """
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchDistribution":
            return
        raise
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _reap_log_group(logs, name: str, *, window_s: float = 20.0) -> None:
    """Delete a Lambda log group in a loop: a late flush can recreate it after one delete."""
    deadline = time.monotonic() + window_s
    while True:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise RuntimeError(f"log group {name}: {exc}") from exc
        if time.monotonic() >= deadline:
            break
        time.sleep(10.0)
    groups = logs.describe_log_groups(logGroupNamePrefix=name).get("logGroups", [])
    if any(g["logGroupName"] == name for g in groups):
        raise RuntimeError(f"log group {name} reappeared after the reap window")


def _zip_source(source: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("index.py", source)
    return buf.getvalue()


def _managed_cache_policy_id(cf, name: str) -> str:
    """Resolve a managed cache policy id from the TARGET's own catalogue, not a constant."""
    marker = None
    while True:
        kwargs = {"Type": "managed", "MaxItems": "100"}
        if marker is not None:
            kwargs["Marker"] = marker
        page = cf.list_cache_policies(**kwargs)["CachePolicyList"]
        for item in page.get("Items", []):
            if item["CachePolicy"]["CachePolicyConfig"]["Name"] == name:
                return item["CachePolicy"]["Id"]
        marker = page.get("NextMarker")
        if marker is None:
            raise AssertionError(f"the managed cache policy {name!r} is not in the target's catalogue")


def _hits(logs, group: str, method: str, nonce: str) -> int:
    """How many times the ORIGIN logged `method` for a request carrying `nonce` (paginated).
    The nonce is minted by this run, so a sibling run or a retry cannot move a count."""
    want = f"SIM2REAL_HIT {method} nonce={nonce}"
    count = 0
    kwargs = {"logGroupName": group, "filterPattern": f'"{nonce}"'}
    while True:
        try:
            page = logs.filter_log_events(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return 0  # the group appears only on the first logged invocation
            raise
        count += sum(1 for e in page.get("events", []) if e["message"].strip() == want)
        token = page.get("nextToken")
        if not token:
            return count
        kwargs["nextToken"] = token


def _nonce(tag: str) -> str:
    return f"{tag}{time.time_ns()}"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """POST refused at the edge and never reaches the origin; direct POST admitted; OPTIONS uncached."""
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    logs = ctx.client("logs")
    account = ctx.client("sts").get_caller_identity()["Account"]
    marker = ctx.unique_name("sim2real-cfmeth-marker-")

    role_name = ctx.unique_name("sim2real-behav-cfmeth-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Description="sim2real request-counting echo origin behind CloudFront",
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    function_name = ctx.unique_name("sim2real-behav-cfmeth-fn-")
    log_group = f"/aws/lambda/{function_name}"
    partition = role_arn.split(":")[1]
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-origin-logs",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": [f"arn:{partition}:logs:{ctx.region}:{account}:log-group:{log_group}",
                         f"arn:{partition}:logs:{ctx.region}:{account}:log-group:{log_group}:*"],
        }]}),
    )
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role_policy(
        RoleName=role_name, PolicyName="sim2real-origin-logs"))
    # Registered BEFORE the function exists, so LIFO reaps the group AFTER delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), log_group))

    def create_function():
        try:
            return lam.create_function(
                FunctionName=function_name, Runtime="python3.12", Role=role_arn,
                Handler="index.handler", Code={"ZipFile": _zip_source(_FUNCTION_SOURCE)},
                Timeout=10, Environment={"Variables": {"SIM2REAL_MARKER": marker}},
                Tags={t["Key"]: t["Value"] for t in _TAG_SET},
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidParameterValueException":
                raise
            return None  # the freshly created role has not propagated yet

    created = _poll_until(create_function, lambda r: r is not None, timeout_s=180.0, interval_s=10.0,
                          description=f"CreateFunction to accept the freshly created role {role_name}")
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function(FunctionName=function_name))
    assert created["FunctionArn"].split(":")[4] == account, (
        f"expected the function in the calling account {account}, got {created['FunctionArn']!r}"
    )
    _poll_until(lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
                lambda state: state == "Active", timeout_s=180.0, interval_s=5.0,
                description=f"lambda function {function_name} to become Active")
    function_url = lam.create_function_url_config(
        FunctionName=function_name, AuthType="AWS_IAM")["FunctionUrl"]
    ctx.on_cleanup(lambda: ctx.client("lambda").delete_function_url_config(
        FunctionName=function_name))
    origin_host = urllib.parse.urlparse(function_url).netloc
    assert urllib.parse.urlparse(function_url).scheme == "https" and origin_host, (
        f"CreateFunctionUrlConfig must return an absolute https URL, got {function_url!r}"
    )

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfmeth-oac-"),
        "OriginAccessControlOriginType": "lambda",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))
    # Query strings forwarded (they carry the nonce); Host NOT forwarded (it would void the OAC sig).
    orp_id = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": ctx.unique_name("sim2real-cfmeth-orp-"),
        "Comment": "sim2real forward query strings to the counting origin",
        "HeadersConfig": {"HeaderBehavior": "none"},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "all"},
    })["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_request_policy,
                                             cf.delete_origin_request_policy, orp_id))
    caching_disabled = _managed_cache_policy_id(cf, "Managed-CachingDisabled")
    caching_optimized = _managed_cache_policy_id(cf, "Managed-CachingOptimized")

    get_head = {"Quantity": 2, "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}}
    get_head_options = {"Quantity": 3, "Items": ["GET", "HEAD", "OPTIONS"],
                        "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]}}
    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-behav-cfmeth-cr-"),
            "Comment": "sim2real AllowedMethods enforcement",
            "Enabled": True,
            "IsIPV6Enabled": False,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "echo",
                "DomainName": origin_host,
                "CustomOriginConfig": {
                    "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    "OriginReadTimeout": 30, "OriginKeepaliveTimeout": 5,
                },
                "OriginAccessControlId": oac_id,
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "echo", "ViewerProtocolPolicy": "https-only",
                "AllowedMethods": get_head,
                "CachePolicyId": caching_disabled, "OriginRequestPolicyId": orp_id,
            },
            "CacheBehaviors": {"Quantity": 1, "Items": [{
                "PathPattern": "/opt/*",
                "TargetOriginId": "echo", "ViewerProtocolPolicy": "https-only",
                "AllowedMethods": get_head_options,
                "CachePolicyId": caching_optimized, "OriginRequestPolicyId": orp_id,
            }]},
        },
        "Tags": {"Items": _TAG_SET},
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    lam.add_permission(FunctionName=function_name, StatementId="sim2real-cf-oac-url",
                       Action="lambda:InvokeFunctionUrl", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist["ARN"], FunctionUrlAuthType="AWS_IAM")
    lam.add_permission(FunctionName=function_name, StatementId="sim2real-cf-oac-fn",
                       Action="lambda:InvokeFunction", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist["ARN"])
    edge, route_headers = ctx.endpoint_route(dist["DomainName"])
    session = requests.Session()
    session.headers.update(route_headers)

    _wait_distribution_deployed(cf, dist_id)

    # Warm-up / positive control: a GET through the GET/HEAD behavior reaches the origin AND is
    # logged. This also absorbs IAM propagation of the logs grant (no API reports it effective).
    def warm_probe():
        nonce = _nonce("w")
        try:
            r = session.get(f"{edge}/?nonce={nonce}", timeout=20)
        except requests.RequestException as exc:
            return ("transport", repr(exc))
        if r.status_code != 200:
            return ("status", r.status_code, r.text[:200])
        return ("logged", _poll_logged(logs, log_group, "GET", nonce))

    def _poll_logged(lg, group, method, nonce):
        deadline = time.monotonic() + 60.0
        while time.monotonic() < deadline:
            if _hits(lg, group, method, nonce) == 1:
                return True
            time.sleep(5.0)
        return False

    try:
        _poll_until(warm_probe, lambda r: r == ("logged", True), timeout_s=420.0, interval_s=10.0,
                    description="a GET through the distribution to reach the origin and be logged")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc

    # BEAT a — POST to both behaviors: CloudFront itself refuses, no origin bytes.
    post_nonce = _nonce("p")
    body = json.dumps({"sim2real": post_nonce}).encode()
    for path in ("/", "/opt/post"):
        refused = session.post(f"{edge}{path}?nonce={post_nonce}", data=body,
                               headers={"content-type": "application/json"}, timeout=20)
        assert refused.status_code == 403, (
            f"POST is not in AllowedMethods for {path!r}, so CloudFront must refuse it: expected 403, "
            f"got {refused.status_code} / {refused.text[:300]!r}"
        )
        x_cache = refused.headers.get("x-cache", "")
        assert x_cache == "Error from cloudfront", (
            f"the refusal of POST {path!r} must be generated by CloudFront, not relayed from the "
            f"origin: expected X-Cache 'Error from cloudfront', got {x_cache!r}"
        )
        assert marker not in refused.text and post_nonce not in refused.text, (
            f"the refused POST {path!r} must carry no origin bytes, got {refused.text[:300]!r}"
        )

    # Differential barrier: a GET issued AFTER the POSTs has reached the origin and been logged, so
    # the POSTs, had CloudFront forwarded them, would have been logged too.
    barrier = _nonce("b")
    b = session.get(f"{edge}/?nonce={barrier}", timeout=20)
    assert b.status_code == 200 and json.loads(b.text)["marker"] == marker, (
        f"barrier GET through the distribution must be served by the origin, got "
        f"{b.status_code} / {b.text[:200]!r}"
    )
    _poll_until(lambda: _hits(logs, log_group, "GET", barrier), lambda n: n == 1, timeout_s=120.0,
                interval_s=5.0, description="the barrier GET to appear in the origin's log")
    leaked = _hits(logs, log_group, "POST", post_nonce)
    assert leaked == 0, (
        f"CloudFront refused the POSTs, so the origin must never have seen them: the origin logged "
        f"{leaked} POST(s) for nonce {post_nonce!r}"
    )

    # BEAT b — the identical POST straight to the origin, SigV4-signed by this check.
    direct_url = f"{function_url.rstrip('/')}/?nonce={post_nonce}"
    aws_req = AWSRequest(method="POST", url=direct_url, data=body,
                         headers={"content-type": "application/json"})
    SigV4Auth(lam._request_signer._credentials.get_frozen_credentials(), "lambda",
              ctx.region).add_auth(aws_req)
    _url, _route = ctx.endpoint_route(direct_url)
    direct = requests.post(_url, data=body, headers={**(dict(aws_req.headers.items())), **_route}, timeout=20)
    assert direct.status_code == 200, (
        f"the origin itself accepts POST: expected 200 from the signed direct call, got "
        f"{direct.status_code} / {direct.text[:300]!r}"
    )
    echoed = json.loads(direct.text)
    assert echoed["method"] == "POST" and echoed["query"] == f"nonce={post_nonce}" and (
        echoed["marker"] == marker), f"the direct POST must be echoed by this run's origin: {echoed!r}"
    assert "x-amz-cf-id" not in echoed["header_names"], (
        f"the direct call must NOT have gone through CloudFront: {echoed['header_names']!r}"
    )
    _poll_until(lambda: _hits(logs, log_group, "POST", post_nonce), lambda n: n >= 1,
                timeout_s=120.0, interval_s=5.0,
                description="the direct POST to appear in the origin's log")
    post_hits = _hits(logs, log_group, "POST", post_nonce)
    assert post_hits == 1, (
        f"the origin must have seen exactly ONE POST for nonce {post_nonce!r} — the direct one — "
        f"got {post_hits}"
    )

    # BEAT c — control: the /opt/* behavior DOES cache GET ...
    get_nonce = _nonce("g")
    get_url = f"{edge}/opt/item?nonce={get_nonce}"
    gets_issued = []

    def cached_get():
        r = session.get(get_url, timeout=20)
        gets_issued.append(r.status_code)
        return r

    hit = _poll_until(cached_get, lambda r: r.headers.get("x-cache") == "Hit from cloudfront",
                      timeout_s=90.0, interval_s=3.0,
                      description="a repeated GET on /opt/* to be served from CloudFront's cache")
    assert json.loads(hit.text)["marker"] == marker, f"cached GET body is not the origin's: {hit.text!r}"

    # ... while OPTIONS (allowed, not cached) reaches the origin every single time.
    opt_nonce = _nonce("o")
    for i in range(3):
        o = session.options(f"{edge}/opt/item?nonce={opt_nonce}", timeout=20)
        assert o.status_code == 200, (
            f"OPTIONS is allowed on /opt/*: expected 200 on request {i + 1}, got {o.status_code} / "
            f"{o.text[:300]!r}"
        )
        echoed = json.loads(o.text)
        assert echoed["method"] == "OPTIONS" and echoed["marker"] == marker, (
            f"OPTIONS {i + 1} must be answered by the origin, got {echoed!r}"
        )
    _poll_until(lambda: _hits(logs, log_group, "OPTIONS", opt_nonce), lambda n: n >= 3,
                timeout_s=120.0, interval_s=5.0,
                description="all three OPTIONS requests to appear in the origin's log")
    opt_hits = _hits(logs, log_group, "OPTIONS", opt_nonce)
    assert opt_hits == 3, (
        f"OPTIONS is not in CachedMethods, so each of the 3 identical OPTIONS must reach the origin: "
        f"origin logged {opt_hits}"
    )
    get_hits = _hits(logs, log_group, "GET", get_nonce)
    assert 1 <= get_hits < len(gets_issued), (
        f"the cached GET control: the origin must have seen at least one but fewer GETs than the "
        f"{len(gets_issued)} issued (a cache Hit answered the rest); origin logged {get_hits}"
    )
    _disable_and_delete_distribution(cf, dist_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
