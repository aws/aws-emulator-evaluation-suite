"""cli-s3-sync-cloudfront-invalidate-workflow."""
from __future__ import annotations

import http.client
import json
import os
import ssl
import subprocess
import tempfile
import time
import urllib.parse

from behavioral_harness import tags
from botocore.exceptions import ClientError
from fidelity_tests_runner import require_tools

CHECK = "cli-s3-sync-cloudfront-invalidate-workflow"
GROUP = "cli-workflow"
SERVICES = ["apigateway", "cloudfront", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """After a CLI re-sync of an updated file to S3 behind a caching distribution, a CloudFront invalidation
    makes the distribution serve the new content instead of the cached copy."""
    require_tools("aws")

    region = ctx.region
    marker = ctx.unique_name("sim2real-cfs3inv-")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-cfs3inv-bkt-").lower().replace("_", "-")
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    local_dir = tempfile.mkdtemp(prefix="sim2real-cfs3inv-")
    asset_path = os.path.join(local_dir, "asset.txt")
    with open(asset_path, "w") as f:
        f.write(f"v1-{marker}")

    _run_shell(ctx, ["aws", "s3", "sync", local_dir, f"s3://{bucket}/"])

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
                "Quantity": 2,
                "Items": ["GET", "HEAD"],
                "CachedMethods": {"Quantity": 2, "Items": ["GET", "HEAD"]},
            },
            "ForwardedValues": {"QueryString": False, "Cookies": {"Forward": "none"}},
            "MinTTL": 0,
            "DefaultTTL": 3600,
            "MaxTTL": 86400,
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

    path = "/asset.txt"
    edge_url, edge_headers = ctx.endpoint_route(dist_domain)
    client = _StickyHTTPSClient(edge_url, verify=ctx.http_verify, headers=edge_headers)
    ctx.on_cleanup(client.close)

    status, body, _ = _poll_sticky(client, path, lambda b: b == f"v1-{marker}", timeout_s=180.0)
    assert status == 200 and body == f"v1-{marker}", f"initial sync not served: {status} {body!r}"

    # "Deployed" only means the distribution's config propagated for routing; the edge cache
    # cluster's own caching activation for a brand-new distribution can lag further. Confirm
    # this specific edge is really serving from cache before trusting that the next fetch
    # (right after the v2 sync) reflects staleness rather than a cold MISS that happens to
    # already carry v2.
    headers_hit = _wait_for_cache_hit(client, path, f"v1-{marker}", timeout_s=180.0)
    assert "hit" in headers_hit.get("X-Cache", "").lower(), (
        f"edge never reported a cache hit for the synced object: {headers_hit}"
    )

    with open(asset_path, "w") as f:
        f.write(f"v2-{marker}")
    _run_shell(ctx, ["aws", "s3", "sync", local_dir, f"s3://{bucket}/"])

    # Same edge, same connection, no invalidation yet: the cache must still hand back the v1
    # bytes it already proved it was holding. Without this beat, a distribution that never
    # cached anything would still pass by coincidence once the invalidation completes below.
    status_stale, body_stale, headers_stale = client.get(path)
    assert status_stale == 200 and body_stale == f"v1-{marker}", (
        f"expected the cached copy to still be served before invalidation, "
        f"got {status_stale} {body_stale!r} (x-cache={headers_stale.get('X-Cache')!r})"
    )

    invalidation_id = _run_aws(
        ctx, "cloudfront", "create-invalidation", "--distribution-id", dist_id, "--paths", path,
    )["Invalidation"]["Id"]
    _wait_invalidation_completed(ctx, dist_id, invalidation_id, timeout_s=600.0)

    status, body, _ = _poll_sticky(client, path, lambda b: b == f"v2-{marker}", timeout_s=120.0)
    assert status == 200 and body == f"v2-{marker}", (
        f"CloudFront still served stale content after invalidation completed: {status} {body!r}"
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


class _StickyHTTPSClient:
    """A GET client that reuses one TCP connection to CloudFront so every request in this
    check lands on the SAME edge location. A fresh connection per request can re-resolve DNS
    to a different, independently-cold edge, making cache-hit/miss behavior look random even
    though the per-edge behavior is deterministic."""

    def __init__(self, url, timeout=15.0, verify=True, headers=None):
        # `url` and `headers` come from ctx.endpoint_route and `verify` from ctx.http_verify.
        parts = urllib.parse.urlsplit(url)
        self.host = parts.netloc
        self.secure = parts.scheme == "https"
        self.prefix = parts.path.rstrip("/")
        self.verify = verify
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.conn = None
        self._connect()

    def _connect(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except Exception:
                pass
        if not self.secure:
            self.conn = http.client.HTTPConnection(self.host, timeout=self.timeout)
            return
        tls = _ssl_context(self.verify)
        self.conn = http.client.HTTPSConnection(self.host, timeout=self.timeout, context=tls)

    def get(self, path):
        for attempt in range(2):
            try:
                self.conn.request("GET", self.prefix + path, headers=self.headers)
                resp = self.conn.getresponse()
                body = resp.read().decode("utf-8", "replace")
                headers = dict(resp.getheaders())
                return resp.status, body, headers
            except Exception:
                if attempt == 1:
                    raise
                self._connect()
        raise AssertionError(f"unreachable: failed to GET {path} from {self.host}")

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def _poll_sticky(client, path, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = (None, "", {})
    while time.monotonic() < deadline:
        try:
            last = client.get(path)
            if last[0] == 200 and predicate(last[1]):
                return last
        except OSError:
            pass
        time.sleep(interval_s)
    raise AssertionError(f"polling {client.host}{path} never satisfied predicate; last={last}")


def _wait_for_cache_hit(client, path, expected_body, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_headers = {}
    while time.monotonic() < deadline:
        status, body, headers = client.get(path)
        last_headers = headers
        if status == 200 and body == expected_body and "hit" in headers.get("X-Cache", "").lower():
            return headers
        time.sleep(interval_s)
    raise AssertionError(
        f"edge cache never reported a Hit for {client.host}{path} within {timeout_s}s; "
        f"last X-Cache={last_headers.get('X-Cache')!r}"
    )


def _cf_wait_deployed(ctx, dist_id, timeout_s=1500.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s")


def _wait_invalidation_completed(ctx, dist_id, invalidation_id, timeout_s=600.0, interval_s=10.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_invalidation(DistributionId=dist_id, Id=invalidation_id)
        if resp["Invalidation"]["Status"] == "Completed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"invalidation {invalidation_id} did not complete within {timeout_s}s")


def _delete_oac(ctx, oac_id):
    cf = ctx.client("cloudfront")
    resp = cf.get_origin_access_control(Id=oac_id)
    cf.delete_origin_access_control(Id=oac_id, IfMatch=resp["ETag"])


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


def _ssl_context(verify):
    """The TLS context for this check's own call to the target, from ``ctx.http_verify``."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
