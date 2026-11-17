"""continuous-deployment-policy-disabled-suppresses-header-routing."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "continuous-deployment-policy-disabled-suppresses-header-routing"
GROUP = "distribution-lifecycle"
SERVICES = ["cloudfront"]

#: SingleHeaderConfig header names must carry this prefix.
_CD_HEADER = "aws-cf-cd-route"

_MANAGED_CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"

_TAGGING = {"Items": [{"Key": "sim2real", "Value": "continuous-deployment-policy-disabled"}]}


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> None:
    """Block until GetDistribution reports Status == 'Deployed'."""
    _poll_until(
        lambda: cf.get_distribution(Id=dist_id)["Distribution"]["Status"],
        lambda status: status == "Deployed",
        timeout_s=timeout_s, interval_s=interval_s,
        description=f"distribution {dist_id} reaching Deployed",
    )


def _update_policy_enabled(cf, policy_id: str, *, enabled: bool, timeout_s=240.0, interval_s=10.0) -> dict:
    """UpdateContinuousDeploymentPolicy, re-fetching ETag on PreconditionFailed.

    A policy can keep settling briefly after it was last read, so a bounded retry re-reads the
    ETag rather than treating one rejection as a check failure.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        current = cf.get_continuous_deployment_policy_config(Id=policy_id)
        config = dict(current["ContinuousDeploymentPolicyConfig"])
        config["Enabled"] = enabled
        try:
            return cf.update_continuous_deployment_policy(
                Id=policy_id, IfMatch=current["ETag"], ContinuousDeploymentPolicyConfig=config
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PreconditionFailed" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _detach_cd_policy(cf, dist_id) -> None:
    """Clear ContinuousDeploymentPolicyId off ``dist_id`` and wait for the clearing to deploy.

    Run as its own cleanup, registered after the policy's delete is registered, so LIFO detaches
    the primary before the policy's delete is attempted — the policy cannot be deleted while a
    distribution still references it.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    if not cfg.get("ContinuousDeploymentPolicyId"):
        return
    cfg["ContinuousDeploymentPolicyId"] = ""
    cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    _wait_deployed(cf, dist_id)


def _disable_and_delete_distribution(cf, dist_id) -> None:
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    _wait_deployed(cf, dist_id)
    etag = cf.get_distribution(Id=dist_id)["ETag"]
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s) in {bucket}: {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _make_origin(ctx, role: str, content: bytes) -> tuple[str, str]:
    """Create a tagged bucket serving one object, and an Origin Access Control for it."""
    s3 = ctx.client("s3")
    cf = ctx.client("cloudfront")
    bucket = ctx.unique_name(f"sim2real-cfcdp-{role}-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": "sim2real", "Value": "continuous-deployment-policy-disabled"}],
    })
    s3.put_object(Bucket=bucket, Key="route.txt", Body=content, ContentType="text/plain")

    oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
        "Name": ctx.unique_name(f"sim2real-cfcdp-{role}-oac-"),
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": "sigv4",
    })["OriginAccessControl"]["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control, cf.delete_origin_access_control, oac_id))
    return bucket, oac_id


def _grant_cloudfront(ctx, bucket: str, dist_arn: str) -> None:
    ctx.client("s3").put_bucket_policy(Bucket=bucket, Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowCloudFrontServicePrincipal",
            "Effect": "Allow",
            "Principal": {"Service": "cloudfront.amazonaws.com"},
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{bucket}/*",
            "Condition": {"StringEquals": {"AWS:SourceArn": dist_arn}},
        }],
    }))


def _origin_entry(origin_id: str, bucket: str, region: str, oac_id: str) -> dict:
    return {
        "Id": origin_id,
        "DomainName": f"{bucket}.s3.{region}.amazonaws.com",
        "S3OriginConfig": {"OriginAccessIdentity": ""},
        "OriginAccessControlId": oac_id,
    }


def _retarget_origin(cf, dist_id: str, bucket: str, region: str, oac_id: str) -> None:
    """Point ``dist_id``'s sole origin at a different bucket+OAC and wait for that to deploy.

    UpdateDistribution requires the full echoed Origin structure (OriginCustomHeaders,
    ConnectionAttempts, ...), not the trimmed shape CreateDistribution accepts — so the existing
    origin is mutated in place rather than replaced.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    origin = cfg["Origins"]["Items"][0]
    origin["DomainName"] = f"{bucket}.s3.{region}.amazonaws.com"
    origin["S3OriginConfig"] = {"OriginAccessIdentity": ""}
    origin["OriginAccessControlId"] = oac_id
    cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    _wait_deployed(cf, dist_id)


def _fetch(session, url, headers, *, timeout_s=180.0, interval_s=5.0):
    """Poll GET ``url`` with ``headers`` until a 200 comes back."""

    def probe():
        try:
            return session.get(url, headers=headers, timeout=15)
        except requests.RequestException:
            return None

    return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                       timeout_s=timeout_s, interval_s=interval_s,
                       description=f"200 from {url} with headers {headers!r}")


def _converge(session, url, headers, expected: bytes, *, timeout_s=240.0, interval_s=5.0):
    """Poll GET ``url``/``headers`` until its body equals ``expected``.

    A policy's Enabled flag can take a short while to reach every edge location after
    UpdateContinuousDeploymentPolicy returns, so the terminal routing is reached by a bounded
    poll rather than read on the first response.
    """

    def probe():
        try:
            r = session.get(url, headers=headers, timeout=15)
        except requests.RequestException:
            return None
        return r.content if r.status_code == 200 else None

    return _poll_until(probe, lambda body: body == expected, timeout_s=timeout_s, interval_s=interval_s,
                       description=f"{url} with headers {headers!r} to serve {expected!r}")


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A SingleHeader continuous deployment policy routes a matching header to the staging
    distribution only while the policy is Enabled; a non-matching header value and a disabled
    policy both route to the primary, and GetContinuousDeploymentPolicy reports Enabled accurately.
    """
    cf = ctx.client("cloudfront")

    primary_bucket, primary_oac = _make_origin(ctx, "prim", b"primary-route")
    staging_bucket, staging_oac = _make_origin(ctx, "stag", b"staging-route")

    primary = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": {
            "CallerReference": ctx.unique_name("sim2real-cfcdp-prim-cr-"),
            "Comment": "sim2real continuous deployment primary",
            "Enabled": True,
            "Origins": {"Quantity": 1, "Items": [_origin_entry("s3origin", primary_bucket, ctx.region, primary_oac)]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_DISABLED,
            },
        },
        "Tags": _TAGGING,
    })["Distribution"]
    primary_id = primary["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, primary_id))
    _grant_cloudfront(ctx, primary_bucket, primary["ARN"])
    _wait_deployed(cf, primary_id)

    primary_etag = cf.get_distribution(Id=primary_id)["ETag"]
    copied = cf.copy_distribution(
        PrimaryDistributionId=primary_id, IfMatch=primary_etag, Staging=True, Enabled=True,
        CallerReference=ctx.unique_name("sim2real-cfcdp-stag-cr-"),
    )["Distribution"]
    staging_id = copied["Id"]
    staging_domain = copied["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, staging_id))
    _wait_deployed(cf, staging_id)

    # CopyDistribution gives the staging copy the SAME origin as the primary; retarget it at the
    # staging bucket so the two distributions serve distinguishable content.
    _retarget_origin(cf, staging_id, staging_bucket, ctx.region, staging_oac)
    staging_arn = cf.get_distribution(Id=staging_id)["Distribution"]["ARN"]
    _grant_cloudfront(ctx, staging_bucket, staging_arn)
    _wait_deployed(cf, staging_id)

    policy = cf.create_continuous_deployment_policy(ContinuousDeploymentPolicyConfig={
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_domain]},
        "Enabled": True,
        "TrafficConfig": {
            "Type": "SingleHeader",
            "SingleHeaderConfig": {"Header": _CD_HEADER, "Value": "staging"},
        },
    })["ContinuousDeploymentPolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_continuous_deployment_policy,
                                             cf.delete_continuous_deployment_policy, policy_id))
    # Registered AFTER the policy's delete so LIFO detaches the primary FIRST: a policy cannot be
    # deleted while a distribution still names it.
    ctx.on_cleanup(lambda: _detach_cd_policy(cf, primary_id))

    primary_cfg_resp = cf.get_distribution_config(Id=primary_id)
    primary_cfg = primary_cfg_resp["DistributionConfig"]
    primary_cfg["ContinuousDeploymentPolicyId"] = policy_id
    cf.update_distribution(Id=primary_id, IfMatch=primary_cfg_resp["ETag"], DistributionConfig=primary_cfg)
    _wait_deployed(cf, primary_id)

    session = requests.Session()
    edge, route_headers = ctx.endpoint_route(primary["DomainName"])
    session.headers.update(route_headers)
    session.verify = ctx.http_verify
    url = f"{edge}/route.txt"

    matching_enabled = _fetch(session, url, {_CD_HEADER: "staging"})
    assert matching_enabled.content == b"staging-route", (
        f"a matching header while the policy was Enabled did not reach staging: {matching_enabled.content!r}"
    )

    mismatched = _fetch(session, url, {_CD_HEADER: "other"})
    assert mismatched.content == b"primary-route", (
        f"a non-matching header value was routed away from the primary: {mismatched.content!r}"
    )

    _update_policy_enabled(cf, policy_id, enabled=False)
    _wait_deployed(cf, primary_id)

    disabled_policy = cf.get_continuous_deployment_policy(Id=policy_id)["ContinuousDeploymentPolicy"]
    disabled_enabled = disabled_policy["ContinuousDeploymentPolicyConfig"]["Enabled"]
    assert disabled_enabled is False, f"expected Enabled False after disabling, got {disabled_enabled!r}"

    matching_disabled = _converge(session, url, {_CD_HEADER: "staging"}, b"primary-route")
    assert matching_disabled == b"primary-route", (
        f"a matching header still reached staging while the policy was disabled: {matching_disabled!r}"
    )

    _update_policy_enabled(cf, policy_id, enabled=True)
    _wait_deployed(cf, primary_id)

    reenabled_policy = cf.get_continuous_deployment_policy(Id=policy_id)["ContinuousDeploymentPolicy"]
    reenabled_enabled = reenabled_policy["ContinuousDeploymentPolicyConfig"]["Enabled"]
    assert reenabled_enabled is True, f"expected Enabled True after re-enabling, got {reenabled_enabled!r}"

    matching_reenabled = _converge(session, url, {_CD_HEADER: "staging"}, b"staging-route")
    assert matching_reenabled == b"staging-route", (
        f"a matching header did not return to staging after re-enabling: {matching_reenabled!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
