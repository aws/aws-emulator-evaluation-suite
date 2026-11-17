"""continuous-deployment-staging-origin-path-promotion-serves-staging-bytes."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "continuous-deployment-staging-origin-path-promotion-serves-staging-bytes"
GROUP = "distribution-lifecycle"
SERVICES = ["cloudfront", "s3"]

#: Must carry the ``aws-cf-cd-`` prefix CloudFront requires for a SingleHeader config header name.
_CD_HEADER = "aws-cf-cd-sim"
_CD_VALUE = "1"

#: The managed CachingDisabled policy: the two origin paths must stay distinguishable by request,
#: never collapsed into one cached response.
_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_PRIMARY_BYTES = b"primary-prefix-bytes"
_STAGING_BYTES = b"staging-prefix-bytes"

#: The longest wait for a distribution to reach Deployed, in the body or in teardown. Declared
#: > 300 s so the derived per-check and teardown budgets lift; a ceiling to fail at, never a
#: latency claim.
_DEPLOYED_DEADLINE_S = 900
_DEPLOY_INTERVAL_S = 15.0
_FETCH_TIMEOUT_S = 240.0
_FETCH_INTERVAL_S = 5.0


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _bounded(ctx, timeout_s: float) -> float:
    """``timeout_s``, cut to the time the runner leaves this body or teardown, less a margin."""
    left = ctx.time_left()
    return timeout_s if left is None else max(1.0, min(timeout_s, left - 15.0))


def _wait_deployed(ctx, cf, dist_id) -> str:
    """Poll GetDistribution to the terminal ``Deployed`` status; return the ETag read there."""
    holder: dict = {}

    def probe() -> str:
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=_bounded(ctx, _DEPLOYED_DEADLINE_S),
                interval_s=_DEPLOY_INTERVAL_S, description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _disable_and_delete_distribution(ctx, cf, dist_id) -> None:
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except cf.exceptions.NoSuchDistribution:
        return
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_deployed(ctx, cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _detach_policy_from_primary(ctx, cf, primary_id: str) -> None:
    try:
        cfg_resp = cf.get_distribution_config(Id=primary_id)
    except cf.exceptions.NoSuchDistribution:
        return
    cfg = cfg_resp["DistributionConfig"]
    if not cfg.get("ContinuousDeploymentPolicyId"):
        return
    cfg["ContinuousDeploymentPolicyId"] = ""
    cf.update_distribution(Id=primary_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    _wait_deployed(ctx, cf, primary_id)


def _delete_policy(cf, policy_id: str) -> None:
    try:
        etag = cf.get_continuous_deployment_policy_config(Id=policy_id)["ETag"]
    except cf.exceptions.NoSuchContinuousDeploymentPolicy:
        return
    cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s) in {bucket}: {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _fetch_until(session, url: str, extra_headers: dict, expected_body: bytes, *, verify):
    """GET ``url`` with ``extra_headers`` until the body equals ``expected_body``; raises on timeout.

    Distribution-wide behaviour can take a moment to reach every edge after a config change
    deploys, so the terminal state polled for is the exact asserted content, not just a 200.
    """
    last = None

    def probe():
        nonlocal last
        try:
            resp = session.get(url, headers=extra_headers, timeout=15, verify=verify)
        except requests.RequestException as exc:
            last = exc
            return None
        last = resp
        return resp

    def done(resp) -> bool:
        return resp is not None and resp.status_code == 200 and resp.content == expected_body

    result = _poll_until(probe, done, timeout_s=_FETCH_TIMEOUT_S, interval_s=_FETCH_INTERVAL_S,
                          description=f"{url} with headers {extra_headers!r} to serve {expected_body!r}")
    return result


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A SingleHeader continuous deployment policy routes a request carrying its header to the
    staging distribution's S3 prefix and a header-free request to the primary's; after
    UpdateDistributionWithStagingConfig, a header-free request gets the former staging bytes.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfcdp-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "cfcdp"}]})
    s3.put_object(Bucket=bucket, Key="primary/obj.txt", Body=_PRIMARY_BYTES, ContentType="text/plain")
    s3.put_object(Bucket=bucket, Key="staging/obj.txt", Body=_STAGING_BYTES, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name("sim2real-behav-cfcdp-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_origin_access_control(
        Id=oac_id, IfMatch=cf.get_origin_access_control(Id=oac_id)["ETag"]))

    def _dist_config(origin_path: str) -> dict:
        return {
            "CallerReference": ctx.unique_name("sim2real-behav-cfcdp-cr-"),
            "Comment": "sim2real-behav continuous deployment staging traffic",
            "Enabled": True,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "s3origin",
                "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                "OriginPath": origin_path,
                "S3OriginConfig": {"OriginAccessIdentity": ""},
                "OriginAccessControlId": oac_id,
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _CACHING_DISABLED,
            },
        }

    primary = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": _dist_config("/primary"),
        "Tags": {"Items": [{"Key": "sim2real", "Value": "cfcdp"}]},
    })["Distribution"]
    primary_id = primary["Id"]
    primary_domain = primary["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, primary_id))
    partition = primary["ARN"].split(":")[1]

    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{partition}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": primary["ARN"]}},
        }],
    }))

    _wait_deployed(ctx, cf, primary_id)

    primary_cfg = cf.get_distribution_config(Id=primary_id)
    staging = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_cfg["ETag"],
        Staging=True,
        Enabled=True,
        CallerReference=ctx.unique_name("sim2real-behav-cfcdp-stage-cr-"),
    )["Distribution"]
    staging_id = staging["Id"]
    staging_domain = staging["DomainName"]
    assert staging_id != primary_id, (
        f"CopyDistribution must mint a distinct staging distribution, got the same id {staging_id!r}"
    )
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, staging_id))
    cf.tag_resource(Resource=staging["ARN"], Tags={"Items": [{"Key": "sim2real", "Value": "cfcdp"}]})

    # Both distribution ARNs now exist, so the policy can admit requests the OAC signs for either.
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:{partition}:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": [primary["ARN"], staging["ARN"]]}},
        }],
    }))

    staging_cfg = cf.get_distribution_config(Id=staging_id)
    staging_conf = staging_cfg["DistributionConfig"]
    staging_conf["Origins"]["Items"][0]["OriginPath"] = "/staging"
    cf.update_distribution(Id=staging_id, IfMatch=staging_cfg["ETag"], DistributionConfig=staging_conf)
    _wait_deployed(ctx, cf, staging_id)

    policy = cf.create_continuous_deployment_policy(ContinuousDeploymentPolicyConfig={
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_domain]},
        "Enabled": True,
        "TrafficConfig": {
            "Type": "SingleHeader",
            "SingleHeaderConfig": {"Header": _CD_HEADER, "Value": _CD_VALUE},
        },
    })["ContinuousDeploymentPolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(lambda: _delete_policy(cf, policy_id))

    fresh_primary_cfg = cf.get_distribution_config(Id=primary_id)
    primary_conf = fresh_primary_cfg["DistributionConfig"]
    primary_conf["ContinuousDeploymentPolicyId"] = policy_id
    cf.update_distribution(Id=primary_id, IfMatch=fresh_primary_cfg["ETag"], DistributionConfig=primary_conf)
    # Registered after the policy's own cleanup so LIFO detaches it from the primary BEFORE trying
    # to delete the policy: a policy still referenced by a distribution cannot be deleted.
    ctx.on_cleanup(lambda: _detach_policy_from_primary(ctx, cf, primary_id))
    _wait_deployed(ctx, cf, primary_id)

    session = requests.Session()
    edge, route = ctx.endpoint_route(primary_domain)
    session.headers.update(route)
    url = f"{edge}/obj.txt"

    staged = _fetch_until(session, url, {_CD_HEADER: _CD_VALUE}, _STAGING_BYTES,
                          verify=ctx.http_verify)
    assert staged.content == _STAGING_BYTES, (
        f"a request carrying {_CD_HEADER!r} must be routed to the staging distribution's prefix: "
        f"got {staged.content!r}"
    )

    unstaged = _fetch_until(session, url, {}, _PRIMARY_BYTES, verify=ctx.http_verify)
    assert unstaged.content == _PRIMARY_BYTES, (
        f"a header-free request must still be routed to the primary distribution's prefix: "
        f"got {unstaged.content!r}"
    )

    primary_etag = cf.get_distribution(Id=primary_id)["ETag"]
    staging_etag = cf.get_distribution(Id=staging_id)["ETag"]
    promoted = cf.update_distribution_with_staging_config(
        Id=primary_id, StagingDistributionId=staging_id,
        IfMatch=f"{primary_etag}, {staging_etag}",
    )
    assert promoted["Distribution"]["Id"] == primary_id, (
        f"UpdateDistributionWithStagingConfig must report the promoted distribution as the "
        f"primary {primary_id!r}, got {promoted['Distribution']['Id']!r}"
    )
    _wait_deployed(ctx, cf, primary_id)

    after_promotion = _fetch_until(session, url, {}, _STAGING_BYTES, verify=ctx.http_verify)
    assert after_promotion.content == _STAGING_BYTES, (
        f"after promotion, a header-free request must get the bytes the header used to require: "
        f"got {after_promotion.content!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
