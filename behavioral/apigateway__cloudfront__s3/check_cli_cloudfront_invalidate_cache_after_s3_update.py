"""cli-cloudfront-invalidate-cache-after-s3-update."""
from __future__ import annotations

import http.client
import json
import os
import ssl
import subprocess
import tempfile
import time
import urllib.parse
import urllib.error
import urllib.request

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cli-cloudfront-invalidate-cache-after-s3-update"
GROUP = "cli-workflow"
SERVICES = ["apigateway", "cloudfront", "s3"]

# NOTE: the managed "CachingOptimized" policy has MinTTL=1s, which revalidates with the
# origin almost immediately -- too fast to reliably observe a "stale" window in this check's
# own timing. Use a custom cache policy with a real TTL floor so the cached response actually
# sticks around long enough for the staleness assertion to be meaningful.
CACHE_POLICY_MIN_TTL = 300


class _StickyHTTPSClient:
    """A GET client that reuses one TCP connection to CloudFront so every request in this
    check lands on the SAME edge location. Without this, each request re-resolves DNS and
    can be routed to a different, independently-cold edge -- making cache-hit/miss behavior
    look random even though the per-edge behavior is deterministic."""

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
        self.conn = http.client.HTTPSConnection(
            self.host, timeout=self.timeout, context=_ssl_context(self.verify)
        )

    def get(self, path):
        for attempt in range(2):
            try:
                self.conn.request("GET", self.prefix + path, headers=self.headers)
                resp = self.conn.getresponse()
                body = resp.read()
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


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """Updating an S3 object behind a cached CloudFront distribution does NOT change what is
    served until an explicit invalidation completes; after invalidation the refreshed content
    is actually delivered."""
    require_tools("aws")

    bucket = ctx.unique_name("sim2real-cf-inval-")
    _create_bucket(ctx, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    key = "page.html"
    body_v1 = b"content-version-1"
    body_v2 = b"content-version-2-refreshed"
    _put_object_file(ctx, bucket, key, body_v1)

    oac_id = _create_oac(ctx, ctx.unique_name("sim2real-oac-"))
    ctx.on_cleanup(lambda: _delete_oac(ctx, oac_id))

    cache_policy_id = _create_cache_policy(ctx, ctx.unique_name("sim2real-cachepol-"))
    ctx.on_cleanup(lambda: _delete_cache_policy(ctx, cache_policy_id))

    origin_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    caller_ref = ctx.unique_name("sim2real-dist-")
    config = _distribution_config_s3_oac(caller_ref, origin_domain, oac_id, "sim2real cf-invalidation workflow",
                                          cache_policy_id)
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

    path = f"/{key}"
    edge_url, edge_headers = ctx.endpoint_route(dist["domain"])
    client = _StickyHTTPSClient(edge_url, verify=ctx.http_verify, headers=edge_headers)
    ctx.on_cleanup(client.close)

    status, content, headers_v1 = _poll_until_ok(client, path, expected_body=body_v1, timeout_s=180.0, interval_s=10.0)
    assert status == 200 and content == body_v1, (
        f"expected initial fetch of {path!r} to return 200/{body_v1!r}; got status={status} content={content!r}"
    )

    # "Deployed" status only means the distribution's config has propagated for routing; the
    # edge cache cluster's actual caching activation for a brand-new distribution can lag a bit
    # further. Confirm this specific edge is really serving from cache (X-Cache: Hit) before
    # trusting that an update-then-fetch will observe staleness -- otherwise every response is
    # legitimately a cold MISS and there is nothing to go stale.
    headers_hit = _wait_for_cache_hit(client, path, body_v1, timeout_s=180.0, interval_s=5.0)
    assert "hit" in headers_hit.get("X-Cache", "").lower(), (
        f"expected edge to report X-Cache: Hit before mutating the origin; got X-Cache={headers_hit.get('X-Cache')!r}"
    )

    # Update the origin object. Because the behavior uses a caching-enabled policy with a
    # fixed, non-trivial TTL and no Cache-Control override, CloudFront keeps serving the
    # already-cached v1 bytes -- on the SAME edge this sticky client is pinned to -- until it
    # is explicitly invalidated.
    _put_object_file(ctx, bucket, key, body_v2)
    status_stale, content_stale, headers_stale = client.get(path)
    assert status_stale == 200, f"expected stale fetch of {path!r} to still return 200; got status={status_stale}"
    assert content_stale == body_v1, (
        f"expected stale cached content before invalidation; "
        f"v1-fetch x-cache={headers_v1.get('X-Cache')!r} cache-control={headers_v1.get('Cache-Control')!r} "
        f"vs stale-fetch x-cache={headers_stale.get('X-Cache')!r} cache-control={headers_stale.get('Cache-Control')!r} "
        f"age={headers_stale.get('Age')!r} got={content_stale!r}"
    )

    inv_id = _create_invalidation(ctx, dist["id"], path)
    _wait_invalidation_completed(ctx, dist["id"], inv_id)

    status2, content2, _headers2 = _poll_until_ok(client, path, expected_body=body_v2, timeout_s=180.0, interval_s=10.0)
    assert status2 == 200, f"expected post-invalidation fetch of {path!r} to return 200; got status={status2}"
    assert content2 == body_v2, (
        f"expected post-invalidation fetch of {path!r} to serve the refreshed object; "
        f"expected={body_v2!r} got={content2!r}"
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


def _create_bucket(ctx, name):
    s3 = ctx.client("s3")
    region = ctx.region
    # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" -- the bucket still
    # lands in ctx.region either way, this is purely the API's us-east-1-is-the-default quirk.
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


def _create_cache_policy(ctx, name):
    config = {
        "Name": name,
        "Comment": "sim2real fixed-TTL cache policy for staleness testing",
        "DefaultTTL": CACHE_POLICY_MIN_TTL,
        "MaxTTL": CACHE_POLICY_MIN_TTL,
        "MinTTL": CACHE_POLICY_MIN_TTL,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }
    out = _run_aws(ctx, "cloudfront", "create-cache-policy", "--cache-policy-config", json.dumps(config))
    return out["CachePolicy"]["Id"]


def _delete_cache_policy(ctx, policy_id):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_cache_policy(Id=policy_id)
        cf.delete_cache_policy(Id=policy_id, IfMatch=resp["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
            raise


def _distribution_config_s3_oac(caller_ref, origin_domain, oac_id, comment, cache_policy_id):
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
            "CachePolicyId": cache_policy_id,
        },
    }


def _create_distribution(ctx, dist_config):
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(dist_config, f)
        path = f.name
    try:
        out = _run_aws(ctx, "cloudfront", "create-distribution", "--distribution-config", f"file://{path}")
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


def _create_invalidation(ctx, dist_id, path):
    cf = ctx.client("cloudfront")
    ref = f"sim2real-{time.time_ns()}"
    resp = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={"Paths": {"Quantity": 1, "Items": [path]}, "CallerReference": ref},
    )
    return resp["Invalidation"]["Id"]


def _wait_invalidation_completed(ctx, dist_id, inv_id, timeout_s=600.0, interval_s=10.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cf.get_invalidation(DistributionId=dist_id, Id=inv_id)
        status = resp["Invalidation"]["Status"]
        if status == "Completed":
            return
        time.sleep(interval_s)
    raise AssertionError(f"invalidation {inv_id} did not complete within {timeout_s}s (last status={status})")


def _poll_until_ok(client, path, expected_body=None, timeout_s=120.0, interval_s=5.0):
    """GET ``path`` on the sticky client's one connection until it serves 200 and the expected body."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        status, body, headers = client.get(path)
        last = (status, body[:200] if isinstance(body, bytes) else body, headers)
        if status == 200 and (expected_body is None or body == expected_body):
            return status, body, headers
        time.sleep(interval_s)
    raise AssertionError(f"GET {client.host}{path} never returned expected result; last={last}")


def _wait_for_cache_hit(client, path, expected_body, timeout_s=180.0, interval_s=5.0):
    """Poll the same edge (sticky connection) until it reports X-Cache: Hit, proving the edge
    cache cluster has actually activated caching for this distribution (not just that the
    distribution's config-propagation Status flipped to Deployed)."""
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


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
