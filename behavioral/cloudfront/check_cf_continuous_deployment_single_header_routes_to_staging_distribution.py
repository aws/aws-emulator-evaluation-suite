"""cf-continuous-deployment-single-header-routes-to-staging-distribution."""
from __future__ import annotations

import json
import time

import requests

from behavioral_harness import tags

CHECK = "cf-continuous-deployment-single-header-routes-to-staging-distribution"
GROUP = 'distribution-lifecycle'
SERVICES = ['cloudfront']

#: An endpoint data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

#: The header CloudFront routes on. `aws-cf-cd-` is the required prefix for a
#: SingleHeaderConfig header name.
_CD_HEADER = "aws-cf-cd-fidelity"

#: Only resources with an ARN (S3 buckets, distributions) can carry this — Origin Access Control
#: and continuous-deployment-policy have no ARN and cannot be tagged, and they are not billed
#: while orphaned.
_MANAGED_TAGGING = {"Items": [{"Key": "sim2real:managed", "Value": "true"}]}


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_distribution_deployed(cf, dist_id, *, timeout_s=900.0, interval_s=10.0) -> str:
    """Poll GetDistribution until Status == 'Deployed'; return the ETag read at that moment.

    Create -> Deployed and disable -> Deployed each typically take a few minutes; 900 s leaves a
    wide margin.
    """
    holder = {"etag": ""}

    def probe() -> str:
        r = cf.get_distribution(Id=dist_id)
        holder["etag"] = r["ETag"]
        return r["Distribution"]["Status"]

    _poll_until(probe, lambda s: s == "Deployed", timeout_s=timeout_s, interval_s=interval_s,
                description=f"distribution {dist_id} to reach Deployed")
    return holder["etag"]


def _detach_continuous_deployment_policy(cf, dist_id) -> None:
    """Clear ContinuousDeploymentPolicyId off the primary and wait for that to deploy.

    Registered as its OWN cleanup ahead of the policy's delete, because a continuous-deployment
    policy cannot be deleted while a distribution still references it, and a staging distribution
    cannot be deleted while a policy still names it. Without this step the teardown deadlocks and
    leaves two distributions plus a policy behind.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    if not cfg.get("ContinuousDeploymentPolicyId"):
        return
    cfg["ContinuousDeploymentPolicyId"] = ""
    cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    _wait_distribution_deployed(cf, dist_id)


def _disable_and_delete_distribution(cf, dist_id) -> None:
    """Disable, wait for that change to deploy, then delete.

    DeleteDistribution issued immediately after the disabling UpdateDistribution is
    refused with ``DistributionNotDisabled``, so the second Deployed wait is mandatory rather than
    defensive. A distribution left enabled cannot be found by name later,
    because its id is server-minted.
    """
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _empty_and_delete_bucket(s3, bucket) -> None:
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _make_origin_bucket(ctx, tag: str, content: bytes) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(f"sim2real-behav-cfcd-{tag}-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={
        "TagSet": [{"Key": "sim2real:managed", "Value": "true"}],
    })
    s3.put_object(Bucket=bucket, Key="obj.txt", Body=content, ContentType="text/plain")
    return bucket


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


def _fetch(session, url, headers, *, timeout_s=180.0, interval_s=5.0):
    """GET until 200; DATAPLANE_MARKER on exhaustion."""
    last = None

    def probe():
        nonlocal last
        try:
            last = session.get(url, headers=headers, timeout=15)
            return last
        except Exception as exc:  # noqa: BLE001 — transient during edge propagation; recorded
            last = exc
            return None

    try:
        return _poll_until(probe, lambda r: r is not None and r.status_code == 200,
                           timeout_s=timeout_s, interval_s=interval_s,
                           description=f"200 from {url} with headers {headers!r}")
    except AssertionError as exc:
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc


@tags("axis:happy-path", "concern:data-plane", "dp:endpoint", "plane:data", "cap:c1")
def run(ctx) -> None:
    """A continuous-deployment SingleHeader policy routes a request carrying the header to the staging
    distribution's origin and an otherwise identical request to the primary's, at the same domain.
    """
    cf = ctx.client("cloudfront")

    primary_bucket = _make_origin_bucket(ctx, "prim", b"primary-origin")
    staging_bucket = _make_origin_bucket(ctx, "stag", b"staging-origin")

    def _oac(tag: str) -> str:
        oac_id = cf.create_origin_access_control(OriginAccessControlConfig={
            "Name": ctx.unique_name(f"sim2real-behav-cfcd-{tag}-oac-"),
            "OriginAccessControlOriginType": "s3",
            "SigningBehavior": "always",
            "SigningProtocol": "sigv4",
        })["OriginAccessControl"]["Id"]
        ctx.on_cleanup(lambda: _delete_with_etag(cf.get_origin_access_control,
                                                 cf.delete_origin_access_control, oac_id))
        return oac_id

    primary_oac = _oac("prim")
    staging_oac = _oac("stag")

    def _dist_config(tag: str, bucket: str, oac_id: str, *, staging: bool) -> dict:
        return {
            "CallerReference": ctx.unique_name(f"sim2real-behav-cfcd-{tag}-cr-"),
            "Comment": f"sim2real continuous deployment {tag}",
            "Enabled": True,
            "Staging": staging,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "s3origin",
                "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                "S3OriginConfig": {"OriginAccessIdentity": ""},
                "OriginAccessControlId": oac_id,
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "allow-all",
                # CachingDisabled: routing, not caching, is under test — a cached copy from the
                # wrong distribution would make the two legs indistinguishable.
                "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
            },
        }

    primary = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": _dist_config("prim", primary_bucket, primary_oac, staging=False),
        "Tags": _MANAGED_TAGGING,
    })["Distribution"]
    primary_id = primary["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, primary_id))
    _grant_cloudfront(ctx, primary_bucket, primary["ARN"])

    staging = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": _dist_config("stag", staging_bucket, staging_oac, staging=True),
        "Tags": _MANAGED_TAGGING,
    })["Distribution"]
    staging_id = staging["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(cf, staging_id))
    _grant_cloudfront(ctx, staging_bucket, staging["ARN"])

    _wait_distribution_deployed(cf, primary_id)
    _wait_distribution_deployed(cf, staging_id)

    cd_policy = cf.create_continuous_deployment_policy(ContinuousDeploymentPolicyConfig={
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging["DomainName"]]},
        "Enabled": True,
        "TrafficConfig": {
            "Type": "SingleHeader",
            "SingleHeaderConfig": {"Header": _CD_HEADER, "Value": "staging"},
        },
    })["ContinuousDeploymentPolicy"]
    cd_id = cd_policy["Id"]
    ctx.on_cleanup(lambda: _delete_with_etag(cf.get_continuous_deployment_policy,
                                             cf.delete_continuous_deployment_policy, cd_id))

    cfg_resp = cf.get_distribution_config(Id=primary_id)
    cfg = cfg_resp["DistributionConfig"]
    cfg["ContinuousDeploymentPolicyId"] = cd_id
    cf.update_distribution(Id=primary_id, IfMatch=cfg_resp["ETag"], DistributionConfig=cfg)
    # Registered AFTER the policy's own cleanup so LIFO detaches BEFORE it tries to delete: the
    # policy cannot be deleted while the primary references it.
    ctx.on_cleanup(lambda: _detach_continuous_deployment_policy(cf, primary_id))
    _wait_distribution_deployed(cf, primary_id)

    session = requests.Session()
    edge, route = ctx.endpoint_route(primary['DomainName'])
    session.headers.update(route)
    url = f"{edge}/obj.txt"

    staged_resp = _fetch(session, url, {_CD_HEADER: "staging"})
    primary_resp = _fetch(session, url, {})

    assert staged_resp.status_code == 200 and primary_resp.status_code == 200, (
        f"statuses were {(staged_resp.status_code, primary_resp.status_code)!r}"
    )
    assert staged_resp.content == b"staging-origin", (
        f"the {_CD_HEADER} header did not route to the staging distribution: "
        f"{staged_resp.content!r}"
    )
    assert primary_resp.content == b"primary-origin", (
        f"a header-free request was routed to staging: {primary_resp.content!r}"
    )

    policy = cf.get_continuous_deployment_policy(Id=cd_id)["ContinuousDeploymentPolicy"]
    assert policy["ContinuousDeploymentPolicyConfig"]["Enabled"] is True, (
        f"the policy that just routed traffic reports itself disabled: {policy!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
