"""cli-deploy-apigw-cloudfront-distribution-workflow."""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import tempfile
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cli-deploy-apigw-cloudfront-distribution-workflow"
GROUP = "cli-workflow"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CLI creates an API Gateway REST API and a CloudFront distribution whose custom
    origin is that API, then requests to the CloudFront domain are shown to actually
    reach the API and return the API's response body (not just CREATE_COMPLETE)."""
    require_tools("aws")

    region = ctx.region
    marker = ctx.unique_name("sim2real-cfapigw-")

    # --- API Gateway: minimal REST API with a MOCK GET method that echoes the marker ---
    api_id = _run_aws(
        ctx, "apigateway", "create-rest-api", "--name", ctx.unique_name("sim2real-api-"),
        "--endpoint-configuration", "types=REGIONAL",
        "--tags", json.dumps({"sim2real": CHECK}),
    )["id"]
    ctx.on_cleanup(lambda: ctx.client("apigateway").delete_rest_api(restApiId=api_id))

    resources = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)
    root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")

    _run_aws(
        ctx, "apigateway", "put-method", "--rest-api-id", api_id, "--resource-id", root_id,
        "--http-method", "GET", "--authorization-type", "NONE",
    )
    _run_aws(
        ctx, "apigateway", "put-method-response", "--rest-api-id", api_id,
        "--resource-id", root_id, "--http-method", "GET", "--status-code", "200",
    )
    _run_aws(
        ctx, "apigateway", "put-integration", "--rest-api-id", api_id, "--resource-id", root_id,
        "--http-method", "GET", "--type", "MOCK",
        "--request-templates", json.dumps({"application/json": '{"statusCode": 200}'}),
    )
    _run_aws(
        ctx, "apigateway", "put-integration-response", "--rest-api-id", api_id,
        "--resource-id", root_id, "--http-method", "GET", "--status-code", "200",
        "--response-templates", json.dumps({"application/json": json.dumps({"marker": marker})}),
    )
    _run_aws(
        ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", "prod",
    )

    apigw_domain = f"{api_id}.execute-api.{region}.amazonaws.com"

    # sanity: the API itself must actually answer before we blame CloudFront for anything
    status, body, _ = _poll_http(f"{ctx.api_url(api_id, 'prod')}/", timeout_s=60.0, verify=ctx.http_verify)
    assert status == 200, f"API Gateway itself did not respond 200: {status} {body!r}"
    assert json.loads(body) == {"marker": marker}, f"API Gateway did not serve the exact marker payload: {body!r}"

    # --- CloudFront: custom origin pointed at the API Gateway stage ---
    dist_config = {
        "CallerReference": marker,
        "Comment": marker,
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "apigw-origin",
                    "DomainName": apigw_domain,
                    "OriginPath": "/prod",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "apigw-origin",
            "ViewerProtocolPolicy": "allow-all",
            "AllowedMethods": {
                "Quantity": 2,
                "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
            },
            "ForwardedValues": {"QueryString": True, "Cookies": {"Forward": "all"}},
            "MinTTL": 0,
            "DefaultTTL": 0,
            "MaxTTL": 0,
            "Compress": False,
        },
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(dist_config, f)
        config_path = f.name
    try:
        created = _run_aws(ctx, "cloudfront", "create-distribution", "--distribution-config", f"file://{config_path}")
    finally:
        os.unlink(config_path)

    dist_id = created["Distribution"]["Id"]
    dist_arn = created["Distribution"]["ARN"]
    dist_domain = created["Distribution"]["DomainName"]
    ctx.client("cloudfront").tag_resource(
        Resource=dist_arn, Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _cf_disable_and_delete(ctx, dist_id))

    _cf_wait_deployed(ctx, dist_id, timeout_s=1500.0)

    edge_url, edge_headers = ctx.endpoint_route(f"{dist_domain}/")
    status, body, _ = _poll_http(edge_url, timeout_s=180.0, headers=edge_headers, verify=ctx.http_verify)
    assert status == 200, f"CloudFront did not return 200 from API Gateway origin: {status} {body!r}"
    assert json.loads(body) == {"marker": marker}, (
        f"CloudFront response did not carry through the API Gateway payload unmodified: {body!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command, shell=isinstance(command, str), env=env, capture_output=True,
        text=True, timeout=timeout_s, cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(ctx, ["aws", "--output", "json", *args], timeout_s=timeout_s, check=check)
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _http_get(url, timeout=10.0, headers=None, method="GET", verify=True):
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


def _poll_http(url, timeout_s=60.0, interval_s=3.0, *, verify=True, **kwargs):
    deadline = time.monotonic() + timeout_s
    last = (None, "", {})
    while time.monotonic() < deadline:
        try:
            last = _http_get(url, **kwargs, verify=verify)
            if last[0] and last[0] < 500:
                return last
        except OSError:
            pass
        time.sleep(interval_s)
    return last


def _cf_wait_deployed(ctx, dist_id, timeout_s=1500.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s")


def _cf_disable_and_delete(ctx, dist_id):
    cf = ctx.client("cloudfront")
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        update_resp = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)
        etag = update_resp["ETag"]
    deadline = time.monotonic() + 1500.0
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            etag = cf.get_distribution_config(Id=dist_id)["ETag"]
            break
        time.sleep(15.0)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
