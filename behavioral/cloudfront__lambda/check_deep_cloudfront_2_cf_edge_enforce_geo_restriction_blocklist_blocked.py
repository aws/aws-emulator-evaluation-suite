"""deep-cloudfront-2-cf-edge-enforce-geo-restriction-blocklist-blocked."""
from __future__ import annotations

import io
import json
import re
import time
import urllib.parse
import zipfile

import requests
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudfront-2-cf-edge-enforce-geo-restriction-blocklist-blocked"
GROUP = "security"
SERVICES = ["cloudfront", "lambda"]

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_TAG_SET = [{"Key": "sim2real", "Value": "behavioral"}]

#: Several consecutive identical edge answers before a phase counts as propagated.
_STABLE_N = 3

#: The origin echoes the marker it was configured with, the method, the raw query string (which
#: carries a per-request nonce, so a cached or fabricated answer cannot pass), the viewer-country
#: header CloudFront added, and the header NAMES it saw (to prove CloudFront was the caller).
_FUNCTION_SOURCE = '''\
import json
import os


def handler(event, context):
    headers = event.get("headers") or {}
    return {
        "statusCode": 200,
        "headers": {"content-type": "application/json"},
        "body": json.dumps({
            "marker": os.environ["SIM2REAL_MARKER"],
            "method": event["requestContext"]["http"]["method"],
            "query": event.get("rawQueryString", ""),
            "viewer_country": headers.get("cloudfront-viewer-country"),
            "header_names": sorted(headers),
        }),
    }
'''


# ===== helpers =====
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

    Called in the body on every path and registered as the ctx.on_cleanup net; a no-op once
    the distribution is gone.
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


def _reap_log_group(logs, name: str, *, window_s: float = 10.0) -> None:
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


def _create_echo_origin(ctx, lam, iam, account: str, marker: str, prefix: str) -> tuple[str, str]:
    """Role + function + AWS_IAM function URL; returns (function_name, function_url)."""
    role_name = ctx.unique_name(f"{prefix}-role-")
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
        Description="sim2real echo origin behind CloudFront",
        Tags=_TAG_SET,
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: ctx.client("iam").delete_role(RoleName=role_name))

    function_name = ctx.unique_name(f"{prefix}-fn-")
    # Registered BEFORE the function exists so LIFO runs it after delete_function. The role grants
    # no logs permissions, so no group is expected; the reap is the net if the target creates one.
    ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{function_name}"))

    def create_function():
        try:
            return lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": _zip_source(_FUNCTION_SOURCE)},
                Timeout=10,
                Environment={"Variables": {"SIM2REAL_MARKER": marker}},
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
    return function_name, function_url


def _grant_distribution(lam, function_name: str, dist_arn: str) -> None:
    """Both grants CloudFront documents for an OAC-signed function URL origin, scoped to one dist."""
    lam.add_permission(FunctionName=function_name, StatementId="sim2real-cf-oac-url",
                       Action="lambda:InvokeFunctionUrl", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist_arn, FunctionUrlAuthType="AWS_IAM")
    lam.add_permission(FunctionName=function_name, StatementId="sim2real-cf-oac-fn",
                       Action="lambda:InvokeFunction", Principal="cloudfront.amazonaws.com",
                       SourceArn=dist_arn)


def _edge_get(session, url: str):
    try:
        return session.get(url, timeout=20)
    except requests.RequestException as exc:  # transport only, during edge propagation
        return exc


def _stable(session, base: str, want_status: int, *, timeout_s: float, what: str) -> list:
    """Poll the edge until `_STABLE_N` consecutive fresh-nonce GETs all answer `want_status`."""
    run: list = []

    def probe():
        nonce = f"n{time.time_ns()}"
        r = _edge_get(session, f"{base}?nonce={nonce}")
        if isinstance(r, requests.Response) and r.status_code == want_status:
            run.append((nonce, r))
        else:
            run.clear()
        return r

    try:
        _poll_until(probe, lambda _r: len(run) >= _STABLE_N, timeout_s=timeout_s, interval_s=5.0,
                    description=f"{_STABLE_N} consecutive {want_status}s through the edge ({what})")
    except AssertionError as exc:
        last = _edge_get(session, f"{base}?nonce=final")
        detail = (f"status={last.status_code} x-cache={last.headers.get('x-cache')!r} "
                  f"body={last.text[:300]!r}" if isinstance(last, requests.Response) else repr(last))
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc} | last probe: {detail}") from exc
    return list(run)


def _set_geo(cf, dist_id: str, restriction_type: str, countries: list) -> None:
    resp = cf.get_distribution_config(Id=dist_id)
    cfg = resp["DistributionConfig"]
    cfg["Restrictions"] = {"GeoRestriction": {
        "RestrictionType": restriction_type,
        "Quantity": len(countries),
        **({"Items": countries} if countries else {}),
    }}
    cf.update_distribution(Id=dist_id, IfMatch=resp["ETag"], DistributionConfig=cfg)
    stored = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]["Restrictions"]
    geo = stored["GeoRestriction"]
    assert geo["RestrictionType"] == restriction_type and sorted(geo.get("Items", [])) == sorted(
        countries), f"expected geo restriction {restriction_type} {countries!r} stored, got {geo!r}"
# ===== end helpers =====


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:endpoint",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Geo blocklist of the viewer's own (discovered) country -> edge 403, no leak; allowlist -> 200."""
    cf = ctx.client("cloudfront")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    marker = ctx.unique_name("sim2real-cfgeo-marker-")

    function_name, function_url = _create_echo_origin(ctx, lam, iam, account, marker,
                                                      "sim2real-behav-cfgeo")
    origin_host = urllib.parse.urlparse(function_url).netloc
    assert urllib.parse.urlparse(function_url).scheme == "https" and origin_host, (
        f"CreateFunctionUrlConfig must return an absolute https URL usable as an origin domain, got "
        f"{function_url!r}"
    )

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfgeo-oac-"),
        "OriginAccessControlOriginType": "lambda",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                             cf.delete_origin_access_control, oac_id))

    # BEAT 1 — forward CloudFront-Viewer-Country (and NOT Host, which would void the OAC signature).
    orp_id = cf.create_origin_request_policy(OriginRequestPolicyConfig={
        "Name": ctx.unique_name("sim2real-cfgeo-orp-"),
        "Comment": "sim2real forward viewer country to the echo origin",
        "HeadersConfig": {"HeaderBehavior": "whitelist",
                          "Headers": {"Quantity": 1, "Items": ["CloudFront-Viewer-Country"]}},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "all"},
    })["OriginRequestPolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_request_policy,
                                             cf.delete_origin_request_policy, orp_id))
    caching_disabled = _managed_cache_policy_id(cf, "Managed-CachingDisabled")

    dist = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-behav-cfgeo-cr-"),
            "Comment": "sim2real geo restriction enforcement",
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
                "TargetOriginId": "echo",
                "ViewerProtocolPolicy": "https-only",
                "CachePolicyId": caching_disabled,
                "OriginRequestPolicyId": orp_id,
            },
            "Restrictions": {"GeoRestriction": {"RestrictionType": "none", "Quantity": 0}},
        },
        "Tags": {"Items": _TAG_SET},
    })["Distribution"]
    dist_id = dist["Id"]
    # Registered before anything else can raise: the id is server-minted.
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, dist_id))
    try:
        _grant_distribution(lam, function_name, dist["ARN"])
        edge, route_headers = ctx.endpoint_route(dist["DomainName"])
        base = f"{edge}/geo"
        session = requests.Session()
        session.headers.update(route_headers)

        _wait_distribution_deployed(cf, dist_id)

        # BEATS 2 + 3 — no restriction: 200 from THIS origin, and the country is read off its echo.
        served = _stable(session, base, 200, timeout_s=300.0, what="no geo restriction")
        countries = set()
        for nonce, resp in served:
            payload = json.loads(resp.text)
            assert payload["marker"] == marker, (
                f"the 200 must come from this run's function: expected marker {marker!r}, got "
                f"{payload.get('marker')!r}"
            )
            assert f"nonce={nonce}" in payload["query"], (
                f"CachingDisabled + all query strings forwarded: the origin must echo this request's "
                f"nonce {nonce!r}, got query {payload['query']!r}"
            )
            assert "x-amz-cf-id" in payload["header_names"], (
                f"the origin request must have come through CloudFront; header names were "
                f"{payload['header_names']!r}"
            )
            countries.add(payload["viewer_country"])
        assert len(countries) == 1, (
            f"the origin request policy forwards CloudFront-Viewer-Country, so every echo must report one "
            f"stable country for this runner; got {sorted(map(repr, countries))!r}"
        )
        country = countries.pop()
        assert isinstance(country, str) and re.fullmatch(r"[A-Z]{2}", country), (
            f"CloudFront-Viewer-Country must be a two-letter ISO 3166-1 alpha-2 code, got {country!r}"
        )

        # BEAT 4 — blocklist the DISCOVERED country: CloudFront itself refuses, nothing leaks.
        _set_geo(cf, dist_id, "blacklist", [country])
        refused = _stable(session, base, 403, timeout_s=900.0, what=f"blacklist [{country}]")
        for nonce, resp in refused:
            x_cache = resp.headers.get("x-cache", "")
            assert x_cache == "Error from cloudfront", (
                f"the geo 403 must be generated by CloudFront, not relayed from the origin: expected "
                f"X-Cache 'Error from cloudfront', got {x_cache!r}"
            )
            assert marker not in resp.text and nonce not in resp.text, (
                f"a geo-blocked request must not leak origin bytes: the refusal body carried the "
                f"marker/nonce: {resp.text[:300]!r}"
            )
            assert "x-amz-cf-id" not in resp.text and '"header_names"' not in resp.text, (
                f"the refusal body must not be the origin's JSON echo, got {resp.text[:300]!r}"
            )

        # BEAT 5 — allowlist the same country: served again, by the origin, with a fresh nonce.
        _set_geo(cf, dist_id, "whitelist", [country])
        restored = _stable(session, base, 200, timeout_s=900.0, what=f"whitelist [{country}]")
        for nonce, resp in restored:
            payload = json.loads(resp.text)
            assert payload["marker"] == marker and f"nonce={nonce}" in payload["query"], (
                f"the allowlisted 200 must be a fresh origin response: marker {payload.get('marker')!r}, "
                f"query {payload.get('query')!r}, expected marker {marker!r} and nonce {nonce!r}"
            )
            assert payload["viewer_country"] == country, (
                f"the allowlisted request must still be resolved to {country!r}, got "
                f"{payload['viewer_country']!r}"
            )
    except BaseException as exc:
        # Torn down in the body on every path: ctx.on_cleanup is bounded at 60 s and
        # disable -> Deployed -> delete takes minutes. A teardown error never masks this failure.
        try:
            _disable_and_delete_distribution(cf, dist_id)
        except BaseException as teardown_exc:
            exc.add_note(f"teardown also failed: {teardown_exc!r}")
        raise
    _disable_and_delete_distribution(cf, dist_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
