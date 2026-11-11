"""list-distributions-by-owned-resource-not-found-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distributions-by-owned-resource-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByOwnedResource refuses the ARN of a real distribution tenant, which
    GetDistributionTenant reads before and after, and the same ARN with a random id alike with
    InvalidArgument "Invalid parameter received. Resource Type": the resource type is checked first."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multitenant_distribution(ctx)
    domain = f"{ctx.unique_name('sim2real-cf-tenant-').lower()}.sim2real-cfbehav-test.com"
    tenant = _create_tenant(ctx, dist_id, domain)
    real_arn = tenant["Arn"]

    # positive control: the tenant exists, by an independent read (GetDistributionTenant by Id,
    # not the create response).
    got = cf.get_distribution_tenant(Identifier=tenant["Id"])
    assert got["DistributionTenant"]["Id"] == tenant["Id"], (
        f"expected {tenant['Id']!r}, got {got['DistributionTenant'].get('Id')!r}"
    )

    # the REAL, existing, owned tenant ARN is rejected with InvalidArgument -- not accepted,
    # and not EntityNotFound -- because "distribution-tenant" is not a resource type this
    # operation supports at all.
    code, message = _error_code_and_message(lambda: cf.list_distributions_by_owned_resource(ResourceArn=real_arn))
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r}"
    assert message == "Invalid parameter received. Resource Type", f"unexpected message {message!r}"

    # same ARN shape, but with the id segment replaced by a fresh random id that cannot exist --
    # rejected with the SAME code, proving the rejection is on resource-type, not on existence.
    fake_arn = real_arn.rsplit("/", 1)[0] + "/" + str(uuid.uuid4())
    fake_code, fake_message = _error_code_and_message(
        lambda: cf.list_distributions_by_owned_resource(ResourceArn=fake_arn)
    )
    assert fake_code == "InvalidArgument", f"expected InvalidArgument, got {fake_code!r}"
    assert fake_message == "Invalid parameter received. Resource Type", f"unexpected message {fake_message!r}"

    # the rejected lookups must not have disturbed the tenant's own existence.
    still_got = cf.get_distribution_tenant(Identifier=tenant["Id"])
    assert still_got["DistributionTenant"]["Id"] == tenant["Id"], (
        f"expected {tenant['Id']!r} still present after the rejected lookups, "
        f"got {still_got['DistributionTenant'].get('Id')!r}"
    )


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-mt-")
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": {
                "CallerReference": caller_ref,
                "Comment": "sim2real multi-tenant test distribution",
                "Enabled": True,
                "ConnectionMode": "tenant-only",
                "Origins": {
                    "Quantity": 1,
                    "Items": [
                        {
                            "Id": "test-origin",
                            "DomainName": "www.example.com",
                            "CustomOriginConfig": {
                                "HTTPPort": 80,
                                "HTTPSPort": 443,
                                "OriginProtocolPolicy": "https-only",
                                "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                            },
                        }
                    ],
                },
                "DefaultCacheBehavior": {
                    "TargetOriginId": "test-origin",
                    "ViewerProtocolPolicy": "https-only",
                    "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
                },
                "HttpVersion": "http2",
            },
            "Tags": {"Items": [{"Key": "sim2real", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str, timeout_s: float = 900.0) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    dist_config = cfg_resp["DistributionConfig"]
    if dist_config.get("Enabled"):
        dist_config["Enabled"] = False
        try:
            cf.update_distribution(Id=dist_id, IfMatch=cfg_resp["ETag"], DistributionConfig=dist_config)
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
    deadline = time.monotonic() + timeout_s
    etag = None
    while time.monotonic() < deadline:
        try:
            got = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        if got["Distribution"]["Status"] == "Deployed":
            etag = got["ETag"]
            break
        time.sleep(15)
    if etag is None:
        return
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _create_tenant(ctx, dist_id: str, domain: str) -> dict:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cf-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=True,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "enabled",
            "PrimaryDomainName": domain,
        },
        Tags={"Items": [{"Key": "sim2real", "Value": "true"}]},
    )
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant["Id"]))
    return tenant


def _delete_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
        etag = got["ETag"]
        if got["DistributionTenant"].get("Enabled"):
            upd = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
