"""list-invalidations-for-tenant-most-recent-first."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-invalidations-for-tenant-most-recent-first"
GROUP = "ordering"
SERVICES = ["cloudfront"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListInvalidationsForDistributionTenant returns a tenant's invalidations ordered
    most-recent-first, and never surfaces another tenant's invalidations."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)

    tenant_a = _create_tenant(ctx, dist_id, "a")
    tenant_b = _create_tenant(ctx, dist_id, "b")

    a_invalidation_ids = []
    for i in range(3):
        inv = cf.create_invalidation_for_distribution_tenant(
            Id=tenant_a,
            InvalidationBatch={
                "CallerReference": ctx.unique_name(f"sim2real-inv-a{i}-"),
                "Paths": {"Quantity": 1, "Items": [f"/tenant-a/{i}/*"]},
            },
        )["Invalidation"]
        a_invalidation_ids.append(inv["Id"])
        # Ensure strictly increasing CreateTime across successive invalidations.
        time.sleep(1.5)

    b_invalidation = cf.create_invalidation_for_distribution_tenant(
        Id=tenant_b,
        InvalidationBatch={
            "CallerReference": ctx.unique_name("sim2real-inv-b-"),
            "Paths": {"Quantity": 1, "Items": ["/tenant-b/*"]},
        },
    )["Invalidation"]

    listed = cf.list_invalidations_for_distribution_tenant(Id=tenant_a)["InvalidationList"][
        "Items"
    ]
    listed_ids = [item["Id"] for item in listed]

    assert set(listed_ids) == set(a_invalidation_ids), "tenant A's invalidation set is wrong"
    assert b_invalidation["Id"] not in listed_ids, "tenant B's invalidation leaked into A's list"

    create_times = [item["CreateTime"] for item in listed]
    assert create_times == sorted(create_times, reverse=True), (
        "ListInvalidationsForDistributionTenant is not ordered most-recent-first"
    )
    # The most recently created invalidation (index 2) must be first in the listing.
    assert listed_ids[0] == a_invalidation_ids[-1], (
        f"expected the most recently created invalidation {a_invalidation_ids[-1]!r} first, "
        f"got {listed_ids[0]!r}"
    )


def _tenant_domain(ctx, tag: str) -> str:
    suffix = ctx.unique_name(f"sim2real-tn-{tag}-")[-30:]
    suffix = "".join(c if (c.isalnum() or c == "-") else "-" for c in suffix.lower())
    suffix = suffix.strip("-") or f"tenant{tag}"
    return f"{suffix}.sim2real-cfbehav-test.com"


def _create_tenant(ctx, dist_id: str, tag: str) -> str:
    cf = ctx.client("cloudfront")
    domain = _tenant_domain(ctx, tag)
    tenant = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name(f"sim2real-tenant-{tag}-")[:100],
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "enabled",
            "PrimaryDomainName": domain,
        },
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _delete_tenant_best_effort(ctx, tenant_id))
    return tenant_id


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-tenant-origin-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    origin_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": ctx.unique_name("sim2real-cf-tenant-"),
                "Comment": "sim2real multi-tenant blueprint",
                "Enabled": True,
                "ConnectionMode": "tenant-only",
                "TenantConfig": {"ParameterDefinitions": []},
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "tenant-origin",
                            "DomainName": origin_domain,
                            "S3OriginConfig": {"OriginAccessIdentity": ""},
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "tenant-origin",
                    "ViewerProtocolPolicy": "allow-all",
                    "CachePolicyId": _CACHING_DISABLED_POLICY_ID,
                },
            },
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_best_effort(ctx, dist_id))
    return dist_id


def _delete_distribution_best_effort(ctx, dist_id: str, timeout_s: float = 1500.0) -> None:
    """A multi-tenant distribution must first be disabled (and finish propagating that
    change) before DeleteDistribution is accepted; this is a bounded best-effort
    teardown (an orphaned enabled distribution has no per-request cost while idle)."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    disabled = False
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        dist = got["Distribution"]
        if dist["Status"] == "Deployed":
            if dist["DistributionConfig"]["Enabled"]:
                if not disabled:
                    cfg = dist["DistributionConfig"]
                    cfg["Enabled"] = False
                    try:
                        cf.update_distribution(Id=dist_id, IfMatch=got["ETag"], DistributionConfig=cfg)
                        disabled = True
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
            else:
                try:
                    cf.delete_distribution(Id=dist_id, IfMatch=got["ETag"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchDistribution":
                        raise
                return
        time.sleep(15)



def _delete_tenant_best_effort(ctx, tenant_id: str, timeout_s: float = 900.0) -> None:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
        if got["DistributionTenant"]["Status"] == "Deployed":
            try:
                cf.delete_distribution_tenant(Id=tenant_id, IfMatch=got["ETag"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "EntityNotFound":
                    raise
            return
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
