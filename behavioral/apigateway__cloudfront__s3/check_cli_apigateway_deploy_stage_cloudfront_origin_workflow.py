"""cli-apigateway-deploy-stage-cloudfront-origin-workflow."""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-apigateway-deploy-stage-cloudfront-origin-workflow"
GROUP = "cli-workflow"
SERVICES = ["apigateway", "cloudfront", "s3"]

CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CLI deploys a REST API stage with a mock integration and fronts it with a CloudFront
    custom origin; the response routed through CloudFront must match the API's own response
    byte-for-byte (proving CloudFront actually proxies to, rather than stubs, the origin)."""
    require_tools("aws")

    api_id, stage_name = _create_mock_api(ctx, ctx.unique_name("sim2real-apigw-"))
    ctx.on_cleanup(lambda: _run_aws(ctx, "apigateway", "delete-rest-api", "--rest-api-id", api_id, check=False))

    expected_body = json.dumps({"message": "hello-from-apigw"}).encode("utf-8")
    direct_url = f"{ctx.rest_api_url(api_id, stage_name)}/hello"
    direct_status, direct_content = _poll_until_http_ok(direct_url, expected_body=expected_body,
                                                          timeout_s=60.0, interval_s=5.0, verify=ctx.http_verify)
    assert direct_status == 200 and direct_content == expected_body, (
        f"API Gateway itself did not serve the mock response: expected status=200 "
        f"body={expected_body!r}, got status={direct_status} body={direct_content!r}"
    )

    origin_domain = f"{api_id}.execute-api.{ctx.region}.amazonaws.com"
    caller_ref = ctx.unique_name("sim2real-dist-")
    config = _distribution_config_apigw_origin(caller_ref, origin_domain, f"/{stage_name}",
                                                "sim2real apigw-cloudfront workflow")
    dist = _create_distribution(ctx, config)
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist["id"]))

    _wait_distribution_deployed(ctx, dist["id"])

    cf_url, cf_headers = ctx.endpoint_route(f"{dist['domain']}/hello")
    status, content = _poll_until_http_ok(
        cf_url, expected_body=expected_body, timeout_s=180.0, interval_s=10.0, headers=cf_headers, verify=ctx.http_verify
    )
    assert status == 200, f"CloudFront did not proxy to the API Gateway origin: expected status=200, got {status}"
    assert content == expected_body, (
        f"CloudFront response body diverged from the API Gateway origin's own response: "
        f"expected {expected_body!r}, got {content!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
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


def _create_mock_api(ctx, name):
    api = _run_aws(ctx, "apigateway", "create-rest-api", "--name", name, "--tags", f"sim2real={CHECK}")
    api_id = api["id"]
    resources = _run_aws(ctx, "apigateway", "get-resources", "--rest-api-id", api_id)
    root_id = next(r["id"] for r in resources["items"] if r["path"] == "/")
    resource = _run_aws(ctx, "apigateway", "create-resource", "--rest-api-id", api_id,
                          "--parent-id", root_id, "--path-part", "hello")
    resource_id = resource["id"]
    _run_aws(ctx, "apigateway", "put-method", "--rest-api-id", api_id, "--resource-id", resource_id,
              "--http-method", "GET", "--authorization-type", "NONE")
    _run_aws(ctx, "apigateway", "put-integration", "--rest-api-id", api_id, "--resource-id", resource_id,
              "--http-method", "GET", "--type", "MOCK",
              "--request-templates", json.dumps({"application/json": '{"statusCode": 200}'}))
    _run_aws(ctx, "apigateway", "put-method-response", "--rest-api-id", api_id, "--resource-id", resource_id,
              "--http-method", "GET", "--status-code", "200")
    _run_aws(ctx, "apigateway", "put-integration-response", "--rest-api-id", api_id, "--resource-id", resource_id,
              "--http-method", "GET", "--status-code", "200",
              "--response-templates", json.dumps({"application/json": json.dumps({"message": "hello-from-apigw"})}))
    stage_name = "prod"
    _run_aws(ctx, "apigateway", "create-deployment", "--rest-api-id", api_id, "--stage-name", stage_name)
    return api_id, stage_name


def _distribution_config_apigw_origin(caller_ref, origin_domain, origin_path, comment):
    return {
        "CallerReference": caller_ref,
        "Comment": comment,
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "apigw-origin",
                    "DomainName": origin_domain,
                    "OriginPath": origin_path,
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
            "ViewerProtocolPolicy": "https-only",
            "CachePolicyId": CACHING_DISABLED_POLICY_ID,
        },
    }


def _create_distribution(ctx, dist_config):
    config_with_tags = {
        "DistributionConfig": dist_config,
        "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(config_with_tags, f)
        path = f.name
    try:
        out = _run_aws(ctx, "cloudfront", "create-distribution-with-tags",
                        "--distribution-config-with-tags", f"file://{path}")
    finally:
        os.unlink(path)
    d = out["Distribution"]
    return {"id": d["Id"], "arn": d["ARN"], "domain": d["DomainName"]}


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1500.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        status = resp["Distribution"]["Status"]
        if status == "Deployed":
            return resp["Distribution"]
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last status={status})")


def _disable_and_delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_distribution(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = resp["Distribution"]["DistributionConfig"]
    etag = resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        try:
            resp2 = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)
            etag = resp2["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "EntityNotFound",
                "NoSuchCachePolicy",
                "NoSuchContinuousDeploymentPolicy",
                "NoSuchDistribution",
                "NoSuchFieldLevelEncryptionConfig",
                "NoSuchOrigin",
                "NoSuchOriginRequestPolicy",
                "NoSuchRealtimeLogConfig",
                "NoSuchResponseHeadersPolicy",
                "TrustedKeyGroupDoesNotExist",
                "TrustedSignerDoesNotExist",
            ):
                raise
    deadline = time.monotonic() + 1500.0
    while time.monotonic() < deadline:
        d = cf.get_distribution(Id=dist_id)
        if d["Distribution"]["Status"] == "Deployed" and not d["Distribution"]["DistributionConfig"]["Enabled"]:
            etag = d["ETag"]
            break
        time.sleep(15.0)
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _http_get(url, timeout=10.0, headers=None, verify=True):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _poll_until_http_ok(url, expected_body=None, timeout_s=120.0, interval_s=5.0, headers=None, verify=True):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status, body = _http_get(url, headers=headers, verify=verify)
        last = (status, body[:200] if isinstance(body, bytes) else body)
        if status == 200 and (expected_body is None or body == expected_body):
            return status, body
        time.sleep(interval_s)
    raise AssertionError(f"GET {url} never returned expected result; last={last}")


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
