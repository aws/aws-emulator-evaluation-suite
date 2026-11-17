"""delete-continuous-deployment-policy-while-attached-to-primary-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-continuous-deployment-policy-while-attached-to-primary-rejected"
GROUP = "distribution-lifecycle"
SERVICES = ["cloudfront", "s3"]

#: The longest wait for a distribution to reach Deployed, in the body or in teardown. Declared
#: > 300 s so the derived per-check and teardown budgets lift; a ceiling to fail at, never a
#: latency claim.
_DEPLOYED_DEADLINE_S = 900
_DEPLOY_INTERVAL_S = 15.0

_IN_USE = (
    "ContinuousDeploymentPolicyInUse",
    "The specified continuous deployment policy is currently associated with a distribution.",
)


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
    """Poll GetDistribution to Status=Deployed; return the ETag read at that moment."""
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


@tags("axis:rejection", "concern:negative-classes", "cap:c1", "plane:control")
def run(ctx) -> None:
    """DeleteContinuousDeploymentPolicy is refused while a primary distribution's
    ContinuousDeploymentPolicyId still names it, and succeeds once detached.
    """
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-cfcdi-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx.client("s3"), bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "cfcdi"}]})

    def _dist_config() -> dict:
        return {
            "CallerReference": ctx.unique_name("sim2real-behav-cfcdi-cr-"),
            "Comment": "sim2real-behav continuous deployment policy in use",
            "Enabled": False,
            "Origins": {"Quantity": 1, "Items": [{
                "Id": "s3origin",
                "DomainName": f"{bucket}.s3.{ctx.region}.amazonaws.com",
                "S3OriginConfig": {"OriginAccessIdentity": ""},
            }]},
            "DefaultCacheBehavior": {
                "TargetOriginId": "s3origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
            },
        }

    primary = cf.create_distribution_with_tags(DistributionConfigWithTags={
        "DistributionConfig": _dist_config(),
        "Tags": {"Items": [{"Key": "sim2real", "Value": "cfcdi"}]},
    })["Distribution"]
    primary_id = primary["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, primary_id))

    primary_cfg = cf.get_distribution_config(Id=primary_id)
    staging = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_cfg["ETag"],
        Staging=True,
        Enabled=True,
        CallerReference=ctx.unique_name("sim2real-behav-cfcdi-stage-cr-"),
    )["Distribution"]
    staging_id = staging["Id"]
    staging_domain = staging["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, cf, staging_id))
    cf.tag_resource(Resource=staging["ARN"], Tags={"Items": [{"Key": "sim2real", "Value": "cfcdi"}]})

    policy = cf.create_continuous_deployment_policy(ContinuousDeploymentPolicyConfig={
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_domain]},
        "Enabled": True,
        "TrafficConfig": {
            "Type": "SingleHeader",
            "SingleHeaderConfig": {"Header": "aws-cf-cd-sim", "Value": "1"},
        },
    })["ContinuousDeploymentPolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(lambda: _delete_policy(cf, policy_id))

    fresh_primary_cfg = cf.get_distribution_config(Id=primary_id)
    primary_conf = fresh_primary_cfg["DistributionConfig"]
    primary_conf["ContinuousDeploymentPolicyId"] = policy_id
    cf.update_distribution(Id=primary_id, IfMatch=fresh_primary_cfg["ETag"], DistributionConfig=primary_conf)
    # Registered after the policy's own cleanup so LIFO detaches it from the primary BEFORE
    # trying to delete the policy: a policy still referenced by a distribution cannot be deleted.
    ctx.on_cleanup(lambda: _detach_policy_from_primary(ctx, cf, primary_id))
    # The in-use refusal is keyed to the primary's deployed config, not merely its submitted one:
    # a delete attempted before the attach itself reaches Deployed answers PreconditionFailed
    # instead.
    _wait_deployed(ctx, cf, primary_id)

    blocked_etag = cf.get_continuous_deployment_policy_config(Id=policy_id)["ETag"]
    try:
        cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=blocked_etag)
    except ClientError as exc:
        error = exc.response["Error"]
        got = (error["Code"], error["Message"])
    else:
        raise AssertionError(
            f"DeleteContinuousDeploymentPolicy must be refused while {policy_id!r} is still "
            f"attached to primary distribution {primary_id!r}, but it succeeded"
        )
    assert got == _IN_USE, f"expected {_IN_USE!r} deleting an attached policy, got {got!r}"

    still_there = cf.get_continuous_deployment_policy(Id=policy_id)["ContinuousDeploymentPolicy"]
    assert still_there["Id"] == policy_id, (
        f"the refused delete must leave the policy readable, got {still_there['Id']!r}"
    )

    _detach_policy_from_primary(ctx, cf, primary_id)
    detached_etag = cf.get_continuous_deployment_policy_config(Id=policy_id)["ETag"]
    cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=detached_etag)

    deleted = False
    try:
        cf.get_continuous_deployment_policy(Id=policy_id)
    except cf.exceptions.NoSuchContinuousDeploymentPolicy:
        deleted = True
    assert deleted, f"policy {policy_id} still readable via GetContinuousDeploymentPolicy after delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
