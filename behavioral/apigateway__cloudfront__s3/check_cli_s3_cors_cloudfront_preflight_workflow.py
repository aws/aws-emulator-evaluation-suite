"""cli-s3-cors-cloudfront-preflight-workflow."""
from __future__ import annotations

import json
import os
import ssl
import subprocess
import tempfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-s3-cors-cloudfront-preflight-workflow"
GROUP = "cli-workflow"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """S3 CORS rules on a bucket behind a CloudFront distribution that forwards the CORS headers answer a
    preflight OPTIONS through the distribution with the bucket's exact Allow-Origin and Allow-Methods values."""
    require_tools("aws")

    region = ctx.region
    marker = ctx.unique_name("sim2real-cfcors-")
    allowed_origin = "https://allowed.example.com"
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-cfcors-bkt-").lower().replace("_", "-")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    s3.put_object(Bucket=bucket, Key="asset.txt", Body=f"v1-{marker}".encode())

    cors_config = {
        "CORSRules": [{
            "AllowedOrigins": [allowed_origin],
            "AllowedMethods": ["GET"],
            "AllowedHeaders": ["*"],
            "MaxAgeSeconds": 3000,
        }]
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(cors_config, f)
        cors_path = f.name
    try:
        _run_aws(ctx, "s3api", "put-bucket-cors", "--bucket", bucket, "--cors-configuration", f"file://{cors_path}")
    finally:
        os.unlink(cors_path)

    oac_id = _run_aws(
        ctx, "cloudfront", "create-origin-access-control",
        "--origin-access-control-config",
        f"Name={marker}-oac,SigningProtocol=sigv4,SigningBehavior=always,OriginAccessControlOriginType=s3",
    )["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))

    origin_domain = f"{bucket}.s3.{region}.amazonaws.com"
    dist_config = {
        "CallerReference": marker,
        "Comment": marker,
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "s3-origin",
                    "DomainName": origin_domain,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                    "OriginAccessControlId": oac_id,
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3-origin",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {
                "Quantity": 3,
                "Items": ["GET", "HEAD", "OPTIONS"],
                "CachedMethods": {"Quantity": 3, "Items": ["GET", "HEAD", "OPTIONS"]},
            },
            "ForwardedValues": {
                "QueryString": False,
                "Cookies": {"Forward": "none"},
                "Headers": {
                    "Quantity": 3,
                    "Items": ["Origin", "Access-Control-Request-Headers", "Access-Control-Request-Method"],
                },
            },
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
    dist_domain = created["Distribution"]["DomainName"]
    ctx.on_cleanup(lambda: _cf_disable_and_delete(ctx, dist_id))

    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": f"arn:aws:cloudfront::{account_id}:distribution/{dist_id}"}},
        }],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy))

    _cf_wait_deployed(ctx, dist_id, timeout_s=1500.0)

    preflight_headers = {
        "Origin": allowed_origin,
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "content-type",
    }
    edge_url, edge_headers = ctx.endpoint_route(f"{dist_domain}/asset.txt")
    status, _, headers = _poll_options(
        edge_url, headers={**preflight_headers, **edge_headers}, timeout_s=180.0, verify=ctx.http_verify,
    )
    headers_lower = {k.lower(): v for k, v in headers.items()}
    assert status in (200, 204), f"preflight through CloudFront did not succeed: {status}"
    assert headers_lower.get("access-control-allow-origin") == allowed_origin, (
        f"CloudFront/S3 CORS preflight did not echo the configured allowed origin: {headers_lower}"
    )
    assert "GET" in headers_lower.get("access-control-allow-methods", ""), (
        f"preflight response missing allowed GET method: {headers_lower}"
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


def _http_options(url, headers=None, timeout=10.0, verify=True):
    import urllib.error
    import urllib.request

    req = urllib.request.Request(url, headers=headers or {}, method="OPTIONS")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_https_context(verify)) as resp:
            return resp.status, resp.read().decode("utf-8", "replace"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


def _poll_options(url, headers, timeout_s=60.0, interval_s=3.0, verify=True):
    deadline = time.monotonic() + timeout_s
    last = (None, "", {})
    while time.monotonic() < deadline:
        try:
            last = _http_options(url, headers=headers, verify=verify)
            if last[0] in (200, 204):
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


def _delete_oac(ctx, oac_id):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_origin_access_control(Id=oac_id)
        cf.delete_origin_access_control(Id=oac_id, IfMatch=resp["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
            raise


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        s3.delete_bucket_policy(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objects += [{"Key": m["Key"], "VersionId": m["VersionId"]} for m in page.get("DeleteMarkers", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


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
