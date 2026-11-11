"""distribution-tenant-unicode-customization-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "distribution-tenant-unicode-customization-round-trip"
GROUP = "representation"
SERVICES = ["cloudfront"]

_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"  # AWS managed


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A distribution tenant created against a multi-tenant distribution with a unicode
    tag value and explicit Customizations/Domains returns those fields byte-identical
    on GetDistributionTenant."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)

    domain = _tenant_domain(ctx, "a")
    unicode_value = "h\u00e9llo-\u4e16\u754c-\u03a9"
    tenant_name = ctx.unique_name("sim2real-tenant-")[:100]

    created = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=tenant_name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "enabled",
            "PrimaryDomainName": domain,
        },
        Customizations={
            "GeoRestrictions": {"RestrictionType": "blacklist", "Locations": ["US", "GB"]}
        },
        Tags={"Items": [{"Key": "sim2real-unicode", "Value": unicode_value}]},
    )["DistributionTenant"]
    tenant_id = created["Id"]
    tenant_arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_tenant_best_effort(ctx, tenant_id))

    assert [d["Domain"] for d in created["Domains"]] == [domain], (
        f"expected create response Domains == [{domain!r}], got {created['Domains']!r}"
    )
    created_tag_values = {t["Key"]: t["Value"] for t in created["Tags"]["Items"]}
    assert created_tag_values["sim2real-unicode"] == unicode_value, (
        f"expected create response tag sim2real-unicode == {unicode_value!r}, got "
        f"{created_tag_values.get('sim2real-unicode')!r}"
    )

    got = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert [d["Domain"] for d in got["Domains"]] == [domain], (
        f"expected GetDistributionTenant Domains == [{domain!r}], got {got['Domains']!r}"
    )
    geo = got["Customizations"]["GeoRestrictions"]
    assert geo["RestrictionType"] == "blacklist", (
        f"expected GeoRestrictions.RestrictionType == 'blacklist', got {geo['RestrictionType']!r}"
    )
    assert sorted(geo["Locations"]) == ["GB", "US"], (
        f"expected GeoRestrictions.Locations == ['GB', 'US'], got {geo['Locations']!r}"
    )

    # Tags are not embedded in GetDistributionTenant's response; ListTagsForResource is the
    # independent, byte-identical read for the tag CloudFront actually persisted.
    listed_tags = cf.list_tags_for_resource(Resource=tenant_arn)["Tags"]["Items"]
    listed_tag_values = {t["Key"]: t["Value"] for t in listed_tags}
    assert listed_tag_values["sim2real-unicode"] == unicode_value, (
        f"expected ListTagsForResource tag sim2real-unicode == {unicode_value!r}, got "
        f"{listed_tag_values.get('sim2real-unicode')!r}"
    )


def _tenant_domain(ctx, tag: str) -> str:
    suffix = ctx.unique_name(f"sim2real-tn-{tag}-")[-30:]
    suffix = "".join(c if (c.isalnum() or c == "-") else "-" for c in suffix.lower())
    suffix = suffix.strip("-") or f"tenant{tag}"
    return f"{suffix}.sim2real-cfbehav-test.com"


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
