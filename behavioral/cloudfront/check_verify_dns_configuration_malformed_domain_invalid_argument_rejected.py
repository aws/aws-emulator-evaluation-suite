"""verify-dns-configuration-malformed-domain-invalid-argument-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "verify-dns-configuration-malformed-domain-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """VerifyDnsConfiguration rejects a malformed domain on a real tenant with InvalidArgument.

    The tenant's own domain is accepted, and without a DNS record it is not reported valid.
    """
    cf = ctx.client("cloudfront")
    dist_id = _create_multitenant_distribution(ctx)
    domain = ctx.unique_name("sim2real-cf-tenant-").replace("_", "-") + ".simparity-sandbox.net"
    tenant = _create_tenant(ctx, dist_id, domains=[domain])
    tenant_id = tenant["Id"]

    malformed_domain = "not a domain !! .."
    code, message = _error_code(
        lambda: cf.verify_dns_configuration(Identifier=tenant_id, Domain=malformed_domain)
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code}"
    expected = (
        "The specified domain name isn't associated with the distribution tenant. "
        "Specify another domain name and try again."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    resp = cf.verify_dns_configuration(Identifier=tenant_id, Domain=domain)
    dns_list = resp["DnsConfigurationList"]
    assert len(dns_list) == 1, f"expected exactly one DnsConfiguration entry, got {len(dns_list)}: {dns_list!r}"
    assert dns_list[0]["Domain"] == domain, f"expected domain {domain!r}, got {dns_list[0]['Domain']!r}"
    status = dns_list[0]["Status"]
    assert status != "valid-configuration", (
        f"domain {domain!r} has no real DNS record pointing at the tenant's routing "
        f"endpoint, but VerifyDnsConfiguration reported {status!r}"
    )


def _error_code(fn):
    """The call's error code and message; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    origin_id = "sim2real-origin"
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real behavioral fixture (multi-tenant)",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",  # AWS managed "CachingDisabled"
        },
    }
    dist = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id) -> None:
    cf = ctx.client("cloudfront")
    etag = None
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            d = cf.get_distribution(Id=dist_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
        if d["Distribution"]["Status"] == "Deployed":
            etag = d["ETag"]
            break
        time.sleep(15)
    if etag is None:
        try:
            etag = cf.get_distribution(Id=dist_id)["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchDistribution":
                raise
            return
    # a distribution must be disabled before it can be deleted
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
        if cfg["DistributionConfig"].get("Enabled"):
            dist_config = cfg["DistributionConfig"]
            dist_config["Enabled"] = False
            upd = cf.update_distribution(Id=dist_id, DistributionConfig=dist_config, IfMatch=cfg["ETag"])
            etag = upd["ETag"]
            deadline = time.monotonic() + 900
            while time.monotonic() < deadline:
                d = cf.get_distribution(Id=dist_id)
                if d["Distribution"]["Status"] == "Deployed":
                    etag = d["ETag"]
                    break
                time.sleep(15)
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
        return
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise


def _create_tenant(ctx, dist_id, domains, connection_group_id=None, name=None, enabled=True):
    cf = ctx.client("cloudfront")
    kwargs = {
        "DistributionId": dist_id,
        "Name": name or ctx.unique_name("sim2real-cf-tenant-"),
        "Domains": [{"Domain": d} for d in domains],
        "Enabled": enabled,
        "ManagedCertificateRequest": {"ValidationTokenHost": "self-hosted"},
        "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    }
    if connection_group_id:
        kwargs["ConnectionGroupId"] = connection_group_id
    tenant = cf.create_distribution_tenant(**kwargs)["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_tenant(ctx, tenant_id))
    return tenant


def _disable_and_delete_tenant(ctx, tenant_id) -> None:
    cf = ctx.client("cloudfront")
    try:
        current = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    etag = current["ETag"]
    if current["DistributionTenant"].get("Enabled"):
        try:
            upd = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
                raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            g = cf.get_distribution_tenant(Identifier=tenant_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        if g["DistributionTenant"]["Status"] == "Deployed":
            etag = g["ETag"]
            break
        time.sleep(10)
    try:
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
