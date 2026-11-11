"""cloudfront-apigateway-wrong-origin-path-negative."""
from __future__ import annotations

import http.client
import json
import ssl
import time
import urllib.parse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-apigateway-wrong-origin-path-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """An origin path that matches no deployed API Gateway stage makes every request fail with the origin's
    403 Missing Authentication Token; correcting the path on the same distribution restores service."""
    api = _create_hello_api(ctx)  # only stage "prod" exists

    # Intentionally mismatched: no "production" stage was ever deployed.
    config = _build_distribution_config(
        ctx,
        comment="sim2real wrong-origin-path negative",
        origin_domain=api["domain"],
        origin_path="/production",
        viewer_protocol_policy="https-only",
    )
    dist_id, dist_domain = _create_distribution(ctx, config)
    _wait_distribution_deployed(ctx, dist_id)

    status, _, body = _poll_http_get(ctx, dist_domain, "/hello")
    assert status == 403, f"expected 403 for a mismatched origin path, got {status}: {body!r}"
    # API Gateway's exact wording for an unresolved stage varies ("Forbidden" when the
    # first path segment doesn't match ANY deployed stage vs. "Missing Authentication
    # Token" when the stage resolves but no resource/method matches underneath it) — the
    # observable effect that matters here is that the origin's error payload is relayed
    # (not fabricated success), so assert the shape rather than the exact phrase.
    error_json = json.loads(body)
    assert "message" in error_json, f"expected an API Gateway error payload, got {body!r}"
    assert error_json != {"message": "hello-from-apigateway"}, (
        f"expected an error payload, not the hello response, got {error_json!r}"
    )
    assert b"hello-from-apigateway" not in body, (
        f"the hello payload must not appear while the origin path is mismatched, got {body!r}"
    )

    # Fix exactly the one broken setting on the SAME distribution.
    _update_origin_path(ctx, dist_id, "/prod")
    _wait_distribution_deployed(ctx, dist_id)

    status2, _, body2 = _poll_http_get(ctx, dist_domain, "/hello")
    assert status2 == 200, f"expected 200 after correcting the origin path, got {status2}: {body2!r}"
    body2_json = json.loads(body2)
    assert body2_json == {"message": "hello-from-apigateway"}, (
        f"expected the hello payload after the fix, got {body2_json!r}"
    )


def _create_hello_api(ctx) -> dict[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-cf-apigw-"), tags={"sim2real-check": CHECK}
    )["id"]
    ctx.on_cleanup(lambda: apigw.delete_rest_api(restApiId=api_id))
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"] if r["path"] == "/")
    hello_id = apigw.create_resource(restApiId=api_id, parentId=root_id, pathPart="hello")["id"]
    apigw.put_method(restApiId=api_id, resourceId=hello_id, httpMethod="GET", authorizationType="NONE")
    apigw.put_integration(
        restApiId=api_id,
        resourceId=hello_id,
        httpMethod="GET",
        type="MOCK",
        requestTemplates={"application/json": '{"statusCode": 200}'},
    )
    apigw.put_method_response(restApiId=api_id, resourceId=hello_id, httpMethod="GET", statusCode="200")
    apigw.put_integration_response(
        restApiId=api_id,
        resourceId=hello_id,
        httpMethod="GET",
        statusCode="200",
        responseTemplates={"application/json": '{"message": "hello-from-apigateway"}'},
    )
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    domain = f"{api_id}.execute-api.{ctx.region}.amazonaws.com"
    return {"api_id": api_id, "domain": domain, "stage": "prod"}


def _build_distribution_config(
    ctx,
    comment: str,
    origin_domain: str,
    origin_path: str,
    viewer_protocol_policy: str = "https-only",
    forward_query: bool = False,
    forward_headers: list[str] | None = None,
    origin_custom_headers: list[tuple[str, str]] | None = None,
) -> dict[str, Any]:
    forward_headers = forward_headers or []
    origin_custom_headers = origin_custom_headers or []
    origin: dict[str, Any] = {
        "Id": "origin1",
        "DomainName": origin_domain,
        "OriginPath": origin_path,
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
        "CustomHeaders": {
            "Quantity": len(origin_custom_headers),
            "Items": [{"HeaderName": h, "HeaderValue": v} for h, v in origin_custom_headers],
        }
        if origin_custom_headers
        else {"Quantity": 0},
    }
    return {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": comment,
        "Enabled": True,
        "Origins": {"Quantity": 1, "Items": [origin]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": viewer_protocol_policy,
            "ForwardedValues": {
                "QueryString": forward_query,
                "Cookies": {"Forward": "none"},
                "Headers": {"Quantity": len(forward_headers), "Items": forward_headers}
                if forward_headers
                else {"Quantity": 0},
            },
            "MinTTL": 0,
            "DefaultTTL": 0,
            "MaxTTL": 0,
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "AllowedMethods": {
                "Quantity": 2,
                "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
            },
        },
    }


def _create_distribution(ctx, config: dict[str, Any]) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id, dist["DomainName"]


def _update_origin_path(ctx, dist_id: str, new_origin_path: str) -> None:
    cf = ctx.client("cloudfront")
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    cfg["Origins"]["Items"][0]["OriginPath"] = new_origin_path
    cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s")


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    deadline = time.monotonic() + 1500.0
    while time.monotonic() < deadline:
        d = cf.get_distribution(Id=dist_id)
        if d["Distribution"]["Status"] == "Deployed" and not d["Distribution"]["DistributionConfig"]["Enabled"]:
            etag = d["ETag"]
            break
        time.sleep(15.0)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _http_get(
    ctx, host: str, path: str, scheme: str | None = None, headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, dict[str, str], bytes]:
    """GET a published host (or a URL) through ``ctx.endpoint_route``, verifying with ``ctx.http_verify``."""
    target, route = ctx.endpoint_route(host if scheme is None else f"{scheme}://{host}")
    headers = {**(headers or {}), **route}
    url = urllib.parse.urlsplit(target)
    if url.scheme == "https":
        conn = http.client.HTTPSConnection(url.netloc, timeout=timeout, context=_ssl_context(ctx))
    else:
        conn = http.client.HTTPConnection(url.netloc, timeout=timeout)
    try:
        conn.request("GET", url.path.rstrip("/") + path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        return resp.status, dict(resp.getheaders()), body
    finally:
        conn.close()


def _ssl_context(ctx):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    verify = ctx.http_verify
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _poll_http_get(
    ctx,
    host: str,
    path: str,
    scheme: str | None = None,
    headers: dict[str, str] | None = None,
    timeout_s: float = 90.0,
    interval_s: float = 5.0,
) -> tuple[int, dict[str, str], bytes]:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return _http_get(ctx, host, path, scheme=scheme, headers=headers)
        except OSError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not reach {host}{path}: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
