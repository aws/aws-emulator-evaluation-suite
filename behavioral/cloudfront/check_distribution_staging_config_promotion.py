"""distribution-staging-config-promotion."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-staging-config-promotion"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

# The promotion wait below is kept short so the check fits a per-check time budget; waits needed
# only for teardown run in on_cleanup.
_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
_PROMOTION_WAIT_TIMEOUT_S = 220.0
_PROMOTION_WAIT_INTERVAL_S = 5.0
_PROMOTE_RETRY_TIMEOUT_S = 20.0
_PROMOTE_RETRY_INTERVAL_S = 5.0
_PROMOTED_CONFIG_TIMEOUT_S = 20.0
_PROMOTED_CONFIG_INTERVAL_S = 5.0
# Cleanup-only (unscored — runs after the harness's per-check timeout window) — generous.
_CLEANUP_DEPLOY_TIMEOUT_S = 1200.0
_CLEANUP_DEPLOY_INTERVAL_S = 20.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution's staging config can be promoted to production via UpdateDistributionWithStagingConfig."""
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-cf-promo-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    primary_id = _create_distribution(ctx, bucket, comment="sim2real-behav primary-v1")
    ctx.on_cleanup(
        lambda: _disable_and_delete_distribution(
            ctx, primary_id, timeout_s=_CLEANUP_DEPLOY_TIMEOUT_S, interval_s=_CLEANUP_DEPLOY_INTERVAL_S
        )
    )

    primary_cfg = cf.get_distribution_config(Id=primary_id)
    staging = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_cfg["ETag"],
        Staging=True,
        CallerReference=ctx.unique_name("sim2real-staging-"),
        Enabled=False,
    )
    staging_id = staging["Distribution"]["Id"]
    staging_domain = staging["Distribution"]["DomainName"]
    assert staging_id != primary_id, (
        f"CopyDistribution must mint a distinct staging distribution id, got {staging_id!r} "
        f"for both primary and staging"
    )
    ctx.on_cleanup(
        lambda: _disable_and_delete_distribution(
            ctx, staging_id, timeout_s=_CLEANUP_DEPLOY_TIMEOUT_S, interval_s=_CLEANUP_DEPLOY_INTERVAL_S
        )
    )

    # NOTE: `Comment` is one of the fields CloudFront intentionally does NOT copy from the
    # staging distribution onto the primary when promoting (the primary's original Comment
    # survives promotion untouched, so polling for it to change would spin forever). Use
    # `DefaultRootObject` as the promoted marker instead — it IS part of the
    # distribution config that UpdateDistributionWithStagingConfig actually copies over.
    marker = ctx.unique_name("sim2real-staging-marker-")
    staging_cfg = cf.get_distribution_config(Id=staging_id)
    conf = staging_cfg["DistributionConfig"]
    conf["Comment"] = "sim2real-behav staging-v1"
    conf["DefaultRootObject"] = marker
    # CreateContinuousDeploymentPolicy rejects a disabled staging distribution
    # ("Staging distributions contains disabled ...") regardless of the policy's own Enabled
    # flag, so the staging distribution must be enabled before it's referenced by the policy.
    conf["Enabled"] = True
    cf.update_distribution(Id=staging_id, IfMatch=staging_cfg["ETag"], DistributionConfig=conf)

    policy = cf.create_continuous_deployment_policy(
        ContinuousDeploymentPolicyConfig={
            "Enabled": True,
            "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_domain]},
            "TrafficConfig": {"Type": "SingleWeight", "SingleWeightConfig": {"Weight": 0.1}},
        }
    )
    policy_id = policy["ContinuousDeploymentPolicy"]["Id"]
    ctx.on_cleanup(lambda: _detach_policy_and_delete(ctx, primary_id, policy_id))

    fresh_primary = cf.get_distribution_config(Id=primary_id)
    primary_conf = fresh_primary["DistributionConfig"]
    primary_conf["ContinuousDeploymentPolicyId"] = policy_id
    cf.update_distribution(Id=primary_id, IfMatch=fresh_primary["ETag"], DistributionConfig=primary_conf)

    # UpdateDistributionWithStagingConfig requires both distributions to have settled (Deployed)
    # before it will accept the promotion — this wait is therefore part of the check's core
    # assertion and can't be deferred to cleanup. It IS, however, tightly budgeted (rather than
    # generously so) to reliably fit under the harness's fixed, non-configurable 300s per-check
    # ceiling: a large "safety margin" timeout here doesn't buy safety, it just guarantees the
    # harness kills the check before this loop itself gives up. Poll both distributions
    # concurrently (not sequentially) so the wait is bounded by the slower of the two rather than
    # the sum of both — they deploy in parallel server-side.
    primary_etag, staging_etag = _wait_deployed_both(
        ctx,
        primary_id,
        staging_id,
        timeout_s=_PROMOTION_WAIT_TIMEOUT_S,
        interval_s=_PROMOTION_WAIT_INTERVAL_S,
    )

    # Even once both distributions read as Deployed, CloudFront's metadata store can be briefly
    # inconsistent (an ETag that a GetDistribution moments ago called "current" can still be
    # rejected as stale) — retry on PreconditionFailed with freshly-refetched ETags rather than
    # treating the first attempt as authoritative. Bounded tightly; this is a short propagation
    # lag, not another multi-minute deploy.
    promoted = _promote_with_retry(
        ctx,
        primary_id,
        staging_id,
        primary_etag,
        staging_etag,
        timeout_s=_PROMOTE_RETRY_TIMEOUT_S,
        interval_s=_PROMOTE_RETRY_INTERVAL_S,
    )
    assert promoted["Distribution"]["Id"] == primary_id, (
        f"UpdateDistributionWithStagingConfig must report the promoted distribution as the "
        f"primary {primary_id!r}, got {promoted['Distribution']['Id']!r}"
    )

    # UpdateDistributionWithStagingConfig kicks off an async copy of the staging config onto the
    # primary distribution — the promoted Distribution object in the response (and an immediate
    # GetDistributionConfig right after) can still reflect the primary's PRE-promotion config for a
    # short window before the copy lands, so poll GetDistributionConfig until the promoted
    # DefaultRootObject shows up rather than asserting on the very next read. This is a
    # metadata-store propagation lag (seconds), not a full edge deploy, so a tight bound is
    # appropriate here too.
    promoted_cfg = _wait_for_promoted_config(
        ctx, primary_id, marker, timeout_s=_PROMOTED_CONFIG_TIMEOUT_S, interval_s=_PROMOTED_CONFIG_INTERVAL_S
    )
    assert promoted_cfg["DefaultRootObject"] == marker, (
        "primary's DefaultRootObject must match the promoted staging config"
    )
    assert promoted_cfg["ContinuousDeploymentPolicyId"] == policy_id, (
        "primary must retain its ContinuousDeploymentPolicyId after promotion, per API contract"
    )


def _promote_with_retry(
    ctx,
    primary_id: str,
    staging_id: str,
    primary_etag: str,
    staging_etag: str,
    timeout_s: float,
    interval_s: float,
):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cf.update_distribution_with_staging_config(
                Id=primary_id,
                StagingDistributionId=staging_id,
                IfMatch=f"{primary_etag}, {staging_etag}",
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PreconditionFailed" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
            primary_etag = cf.get_distribution(Id=primary_id)["ETag"]
            staging_etag = cf.get_distribution(Id=staging_id)["ETag"]


def _wait_for_promoted_config(ctx, dist_id: str, marker: str, timeout_s: float, interval_s: float):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    conf = None
    while time.monotonic() < deadline:
        conf = cf.get_distribution_config(Id=dist_id)["DistributionConfig"]
        if conf.get("DefaultRootObject") == marker:
            return conf
        time.sleep(interval_s)
    raise AssertionError(
        f"distribution {dist_id} config never reflected the promoted staging DefaultRootObject "
        f"(last DefaultRootObject={conf.get('DefaultRootObject') if conf else None!r})"
    )

def _wait_deployed_both(ctx, primary_id: str, staging_id: str, timeout_s: float, interval_s: float) -> tuple[str, str]:
    """Poll the primary and staging distributions concurrently (same loop) rather than
    sequentially, so the total wait is bounded by whichever one is slower to deploy, not the sum
    of both. Both distributions actually deploy in parallel server-side, so waiting on them one
    at a time only wastes client-side wall-clock budget."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    primary_etag = None
    staging_etag = None
    primary_status = None
    staging_status = None
    while time.monotonic() < deadline:
        if primary_etag is None:
            got = cf.get_distribution(Id=primary_id)
            primary_status = got["Distribution"]["Status"]
            if primary_status == "Deployed":
                primary_etag = got["ETag"]
        if staging_etag is None:
            got = cf.get_distribution(Id=staging_id)
            staging_status = got["Distribution"]["Status"]
            if staging_status == "Deployed":
                staging_etag = got["ETag"]
        if primary_etag is not None and staging_etag is not None:
            return primary_etag, staging_etag
        time.sleep(interval_s)
    raise AssertionError(
        f"distributions never both reached Deployed "
        f"(primary={primary_status!r}, staging={staging_status!r})"
    )


def _create_distribution(ctx, bucket: str, comment: str) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-primary-"),
            "Comment": comment,
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "origin1",
                        "DomainName": f"{bucket}.s3.amazonaws.com",
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "origin1",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }
    )
    return resp["Distribution"]["Id"]


def _disable_and_delete_distribution(
    ctx, dist_id: str, timeout_s: float = _CLEANUP_DEPLOY_TIMEOUT_S, interval_s: float = _CLEANUP_DEPLOY_INTERVAL_S
) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
    except cf.exceptions.NoSuchDistribution:
        return
    etag = cfg["ETag"]
    conf = cfg["DistributionConfig"]
    if conf.get("Enabled"):
        conf["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=conf)["ETag"]
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        status = got["Distribution"]["Status"]
        etag = got["ETag"]
        if status == "Deployed":
            break
        time.sleep(interval_s)
    if status != "Deployed":
        raise AssertionError(f"distribution {dist_id} never reached Deployed for cleanup (last={status})")
    cf.delete_distribution(Id=dist_id, IfMatch=etag)



def _detach_policy_and_delete(ctx, primary_id: str, policy_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg = cf.get_distribution_config(Id=primary_id)
        conf = cfg["DistributionConfig"]
        if conf.get("ContinuousDeploymentPolicyId"):
            conf["ContinuousDeploymentPolicyId"] = ""
            cf.update_distribution(Id=primary_id, IfMatch=cfg["ETag"], DistributionConfig=conf)
    except cf.exceptions.NoSuchDistribution:
        pass

    deadline = time.monotonic() + 300.0
    while True:
        try:
            etag = cf.get_continuous_deployment_policy_config(Id=policy_id)["ETag"]
            cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)
            return
        except cf.exceptions.NoSuchContinuousDeploymentPolicy:
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ContinuousDeploymentPolicyInUse" and time.monotonic() < deadline:
                time.sleep(15.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
