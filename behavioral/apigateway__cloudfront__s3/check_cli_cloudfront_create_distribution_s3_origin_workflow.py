"""cli-cloudfront-create-distribution-s3-origin-workflow."""
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

CHECK = "cli-cloudfront-create-distribution-s3-origin-workflow"
GROUP = "cli-workflow"
SERVICES = ["apigateway", "cloudfront", "s3"]

CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CLI creates an S3 bucket+object and an OAC-fronted CloudFront distribution; the object
    is actually served, byte-for-byte, through the CloudFront domain (not just describe-shaped)."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-cf-origin-")
    _create_bucket(ctx, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    key = "index.html"
    body = b"hello-from-s3-origin-v1"
    _put_object_file(ctx, bucket, key, body)

    oac_id = _create_oac(ctx, ctx.unique_name("sim2real-oac-"))
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))

    origin_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    caller_ref = ctx.unique_name("sim2real-dist-")
    config = _distribution_config_s3_oac(caller_ref, origin_domain, oac_id, "sim2real cf-s3 workflow")
    dist = _create_distribution(ctx, config)
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist["id"]))

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCloudFrontServicePrincipal",
                "Effect": "Allow",
                "Principal": {"Service": "cloudfront.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket}/*",
                "Condition": {"StringEquals": {"AWS:SourceArn": dist["arn"]}},
            }
        ],
    }
    ctx.client("s3").put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))

    _wait_distribution_deployed(ctx, dist["id"])

    url, headers = ctx.endpoint_route(f"{dist['domain']}/{key}")
    status, content = _poll_until_http_ok(
        url, expected_body=body, timeout_s=180.0, interval_s=10.0, headers=headers, verify=ctx.http_verify,
    )
    assert status == 200, f"expected 200 serving {url} through CloudFront, got {status}"
    assert content == body, f"expected byte-identical origin content, got {content[:200]!r}"


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


def _create_bucket(ctx, name):
    s3 = ctx.client("s3")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_public_access_block(
        Bucket=name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        resp = s3.list_object_versions(Bucket=name)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _put_object_file(ctx, bucket, key, body):
    with tempfile.NamedTemporaryFile(mode="wb", suffix=".bin", delete=False) as f:
        f.write(body)
        path = f.name
    try:
        _run_aws(ctx, "s3api", "put-object", "--bucket", bucket, "--key", key, "--body", path,
                  "--content-type", "text/plain")
    finally:
        os.unlink(path)


def _create_oac(ctx, name):
    config = {
        "Name": name,
        "Description": "sim2real OAC",
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    }
    out = _run_aws(ctx, "cloudfront", "create-origin-access-control", "--origin-access-control-config",
                    json.dumps(config))
    return out["OriginAccessControl"]["Id"]


def _delete_oac(ctx, oac_id):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_origin_access_control(Id=oac_id)
        cf.delete_origin_access_control(Id=oac_id, IfMatch=resp["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginAccessControl":
            raise


def _distribution_config_s3_oac(caller_ref, origin_domain, oac_id, comment):
    return {
        "CallerReference": caller_ref,
        "Comment": comment,
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "s3-origin",
                    "DomainName": origin_domain,
                    "OriginAccessControlId": oac_id,
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "s3-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": CACHING_DISABLED_POLICY_ID,
        },
    }


def _create_distribution(ctx, dist_config):
    payload = {
        "DistributionConfig": dist_config,
        "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(payload, f)
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
