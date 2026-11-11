"""cloudfront-apigateway-origin-missing-resource-negative."""
from __future__ import annotations

import http.client
import json
import ssl
import time
import urllib.parse
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cloudfront-apigateway-origin-missing-resource-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """With the API Gateway stage behind a CloudFront origin deleted, CloudFront relays the origin's 403
    Missing Authentication Token; redeploying the stage restores service with no CloudFront change."""
    api = _create_hello_api(ctx)
    apigw = ctx.client("apigateway")

    config = _build_distribution_config(
        ctx,
        comment="sim2real origin-missing-resource negative",
        origin_domain=api["domain"],
        origin_path=f"/{api['stage']}",
        viewer_protocol_policy="https-only",
    )
    dist_id, dist_domain = _create_distribution(ctx, config)
    _wait_distribution_deployed(ctx, dist_id)

    # Positive control: the stage exists and is deployed -> the distribution serves it.
    status, _, body = _poll_http_get(ctx, dist_domain, "/hello")
    assert status == 200, f"positive control failed: expected 200, got {status}: {body!r}"
    payload = json.loads(body)
    assert payload == {"message": "hello-from-apigateway"}, f"positive control body mismatch: {payload!r}"

    # Break exactly one thing: remove the stage the origin path points at.
    apigw.delete_stage(restApiId=api["api_id"], stageName=api["stage"])

    def _probe() -> tuple[int, bytes]:
        s, _, b = _http_get(ctx, dist_domain, "/hello")
        return s, b

    deadline = time.monotonic() + 90.0
    final_status, final_body = None, b""
    while time.monotonic() < deadline:
        final_status, final_body = _probe()
        if final_status != 200:
            break
        time.sleep(5.0)
    assert final_status == 403, f"expected 403 after the stage was deleted, got {final_status}: {final_body!r}"
    # API Gateway's exact wording for an unresolved stage varies ("Forbidden" vs.
    # "Missing Authentication Token") — assert the error SHAPE (a relayed origin error,
    # not a fabricated success), not the exact phrase.
    error_json = json.loads(final_body)
    assert "message" in error_json, f"expected an API Gateway error payload, got {final_body!r}"
    assert error_json != {"message": "hello-from-apigateway"}, (
        f"expected a refusal payload, got the fabricated success body: {error_json!r}"
    )
    # The effect (a served hello payload) must be absent, not merely a different status.
    assert b"hello-from-apigateway" not in final_body, (
        f"hello payload leaked into a 403 response: {final_body!r}"
    )

    # Redeploying the stage (no CloudFront config change) must restore service.
    apigw.create_deployment(restApiId=api["api_id"], stageName=api["stage"])
    # CloudFront serves the cached origin error until its error-caching TTL lapses.
    left = ctx.time_left()
    deadline = time.monotonic() + (180.0 if left is None else min(180.0, left))
    status2, _, body2 = _poll_http_get(ctx, dist_domain, "/hello", timeout_s=90.0)
    while status2 != 200 and time.monotonic() < deadline:
        time.sleep(2.0)
        status2, _, body2 = _poll_http_get(ctx, dist_domain, "/hello", timeout_s=90.0)
    assert status2 == 200, f"expected service restored after redeploy, got {status2}: {body2!r}"
    payload2 = json.loads(body2)
    assert payload2 == {"message": "hello-from-apigateway"}, f"restored body mismatch: {payload2!r}"


def _create_hello_api(ctx) -> dict[str, str]:
    apigw = ctx.client("apigateway")
    api_id = apigw.create_rest_api(
        name=ctx.unique_name("sim2real-cf-apigw-"), tags={"sim2real": CHECK}
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
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        }
    )
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id, dist["DomainName"]


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
