"""continuous-deployment-policy-lifecycle."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "continuous-deployment-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ContinuousDeploymentPolicy create->get->update->list->delete transitions correctly."""
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")

    # Real AWS validates StagingDistributionDnsNames against an actual staging distribution's domain
    # (InvalidArgument otherwise) — a syntactically-valid but fabricated "d<random>.cloudfront.net"
    # is rejected. So this needs a REAL staging distribution to get a domain
    # CreateContinuousDeploymentPolicy will accept.
    bucket = ctx.unique_name("sim2real-cf-cdp-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    primary_id = _create_distribution(ctx, bucket)
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, primary_id))

    primary_cfg = cf.get_distribution_config(Id=primary_id)
    staging = cf.copy_distribution(
        PrimaryDistributionId=primary_id,
        IfMatch=primary_cfg["ETag"],
        Staging=True,
        CallerReference=ctx.unique_name("sim2real-cdp-staging-"),
        Enabled=False,
    )
    staging_id = staging["Distribution"]["Id"]
    staging_domain = staging["Distribution"]["DomainName"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, staging_id))

    # CreateContinuousDeploymentPolicy rejects a staging distribution that's disabled
    # ("Staging distributions contains disabled ...") regardless of the policy's own Enabled
    # flag — so the staging distribution must be enabled before it can be referenced.
    staging_cfg = cf.get_distribution_config(Id=staging_id)
    staging_conf = staging_cfg["DistributionConfig"]
    staging_conf["Enabled"] = True
    cf.update_distribution(Id=staging_id, IfMatch=staging_cfg["ETag"], DistributionConfig=staging_conf)

    created = cf.create_continuous_deployment_policy(
        ContinuousDeploymentPolicyConfig={
            "Enabled": False,
            "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_domain]},
            "TrafficConfig": {
                "Type": "SingleWeight",
                "SingleWeightConfig": {"Weight": 0.1},
            },
        }
    )
    policy_id = created["ContinuousDeploymentPolicy"]["Id"]
    create_etag = created["ETag"]
    created_enabled = created["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"]["Enabled"]
    assert created_enabled is False, f"expected Enabled=False on create, got {created_enabled!r}"

    def _cleanup() -> None:
        try:
            etag = cf.get_continuous_deployment_policy_config(Id=policy_id)["ETag"]
        except cf.exceptions.NoSuchContinuousDeploymentPolicy:
            return
        cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    got = cf.get_continuous_deployment_policy(Id=policy_id)
    cfg = got["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"]
    got_items = cfg["StagingDistributionDnsNames"]["Items"]
    assert got_items == [staging_domain], f"expected staging DNS names {[staging_domain]!r}, got {got_items!r}"
    got_weight = cfg["TrafficConfig"]["SingleWeightConfig"]["Weight"]
    assert got_weight == 0.1, f"expected create-time weight 0.1, got {got_weight!r}"

    got_cfg = cf.get_continuous_deployment_policy_config(Id=policy_id)
    assert got_cfg["ETag"] == create_etag, (
        f"GetContinuousDeploymentPolicyConfig ETag {got_cfg['ETag']!r} != create-response ETag {create_etag!r}"
    )

    listed = cf.list_continuous_deployment_policies()
    # Each list item is a ContinuousDeploymentPolicySummary, which wraps the full
    # ContinuousDeploymentPolicy (Id lives one level down), not a flat {"Id": ...} record.
    ids = [
        i["ContinuousDeploymentPolicy"]["Id"]
        for i in listed.get("ContinuousDeploymentPolicyList", {}).get("Items", [])
    ]
    assert policy_id in ids, f"policy {policy_id} missing from ListContinuousDeploymentPolicies: {ids!r}"

    # A freshly-created continuous deployment policy can keep settling on the backend for a short
    # while after CreateContinuousDeploymentPolicy returns — an UpdateContinuousDeploymentPolicy
    # sent with the create-time ETag (even though GetContinuousDeploymentPolicyConfig echoed that
    # SAME ETag moments earlier) can still be rejected with PreconditionFailed ("recent changes ...
    # not yet propagated"). So the update is wrapped in a bounded retry that re-fetches a fresh
    # ETag and resubmits on PreconditionFailed, rather than trusting the ETag stays valid forever.
    update_config = {
        "Enabled": True,
        "StagingDistributionDnsNames": {"Quantity": 1, "Items": [staging_domain]},
        "TrafficConfig": {
            "Type": "SingleWeight",
            "SingleWeightConfig": {"Weight": 0.05},
        },
    }
    updated = _update_policy_with_retry(cf, policy_id, create_etag, update_config)
    update_etag = updated["ETag"]
    assert update_etag != create_etag, f"update ETag {update_etag!r} did not change from create ETag {create_etag!r}"
    updated_enabled = updated["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"]["Enabled"]
    assert updated_enabled is True, f"expected Enabled=True in update response, got {updated_enabled!r}"

    reread = cf.get_continuous_deployment_policy(Id=policy_id)
    reread_cfg = reread["ContinuousDeploymentPolicy"]["ContinuousDeploymentPolicyConfig"]
    assert reread_cfg["Enabled"] is True, f"expected Enabled=True on reread after update, got {reread_cfg['Enabled']!r}"
    reread_weight = reread_cfg["TrafficConfig"]["SingleWeightConfig"]["Weight"]
    assert reread_weight == 0.05, f"expected post-update weight 0.05 on reread, got {reread_weight!r}"

    cf.delete_continuous_deployment_policy(Id=policy_id, IfMatch=update_etag)

    deleted = False
    try:
        cf.get_continuous_deployment_policy(Id=policy_id)
    except cf.exceptions.NoSuchContinuousDeploymentPolicy:
        deleted = True
    assert deleted, f"policy {policy_id} still readable via GetContinuousDeploymentPolicy after delete"


def _update_policy_with_retry(
    cf, policy_id: str, etag: str, config: dict, timeout_s: float = 240.0, interval_s: float = 10.0
) -> dict:
    """UpdateContinuousDeploymentPolicy, retrying on PreconditionFailed with a freshly-refetched
    ETag. Real AWS can keep a just-created policy "settling" briefly, rejecting an update sent
    with an ETag that a GetContinuousDeploymentPolicyConfig call moments earlier confirmed was
    current — so a stale-looking ETag isn't necessarily a check bug, it's the backend still
    catching up. Bounded rather than an unbounded/blind retry."""
    deadline = time.monotonic() + timeout_s
    current_etag = etag
    while True:
        try:
            return cf.update_continuous_deployment_policy(
                Id=policy_id, IfMatch=current_etag, ContinuousDeploymentPolicyConfig=config
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PreconditionFailed" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
            current_etag = cf.get_continuous_deployment_policy_config(Id=policy_id)["ETag"]


def _create_distribution(ctx, bucket: str) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cdp-primary-"),
            "Comment": "sim2real-behav cdp-primary",
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


def _disable_and_delete_distribution(ctx, dist_id: str, timeout_s: float = 1200.0) -> None:
    import time

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
        time.sleep(20.0)
    if status != "Deployed":
        raise AssertionError(f"distribution {dist_id} never reached Deployed for cleanup (last={status})")
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
