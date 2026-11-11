"""list-distribution-tenants-pagination-stable-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "list-distribution-tenants-pagination-stable-ordering"
GROUP = "ordering"
SERVICES = ["cloudfront"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed
_TENANT_COUNT = 5


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionTenants, paginated two items at a time with a marker, returns a
    stable, non-overlapping, deterministic order across pages -- and re-paginating from
    scratch a second time reproduces the exact same order."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)

    expected_ids = set()
    for i in range(_TENANT_COUNT):
        domain = _tenant_domain(ctx, str(i))
        tenant = cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name(f"sim2real-tenant-{i}-")[:100],
            Domains=[{"Domain": domain}],
            Enabled=False,
            ManagedCertificateRequest={
                "ValidationTokenHost": "self-hosted",
                "CertificateTransparencyLoggingPreference": "enabled",
                "PrimaryDomainName": domain,
            },
            Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        )["DistributionTenant"]
        expected_ids.add(tenant["Id"])
        ctx.on_cleanup(lambda tid=tenant["Id"]: _delete_tenant_best_effort(ctx, tid))

    first_pass = _paginate_tenant_ids(ctx, dist_id)
    second_pass = _paginate_tenant_ids(ctx, dist_id)

    assert set(first_pass) == expected_ids, "pagination did not surface every created tenant"
    assert len(first_pass) == len(set(first_pass)), "a page repeated an item already seen"
    assert first_pass == second_pass, "two independent paginated passes returned different orders"


def _tenant_domain(ctx, tag: str) -> str:
    suffix = ctx.unique_name(f"sim2real-tn-{tag}-")[-30:]
    suffix = "".join(c if (c.isalnum() or c == "-") else "-" for c in suffix.lower())
    suffix = suffix.strip("-") or f"tenant{tag}"
    return f"{suffix}.sim2real-cfbehav-test.com"


def _paginate_tenant_ids(ctx, dist_id: str) -> list:
    cf = ctx.client("cloudfront")
    ids: list = []
    marker = ""
    while True:
        kwargs = {"AssociationFilter": {"DistributionId": dist_id}, "MaxItems": 2}
        if marker:
            kwargs["Marker"] = marker
        resp = cf.list_distribution_tenants(**kwargs)
        page_ids = [item["Id"] for item in resp.get("DistributionTenantList", []) or []]
        assert len(page_ids) <= 2, "page returned more items than MaxItems"
        ids.extend(page_ids)
        marker = resp.get("NextMarker")
        if not marker:
            break
    return ids


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cf-tenant-origin-").lower().replace("_", "-")
    # The cloudfront suite's harness region IS us-east-1 (the control plane is global and
    # only lives there), where create_bucket takes no LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))

    origin_domain = f"{bucket}.s3.{ctx.region}.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
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
