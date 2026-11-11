"""update-domain-association-not-found-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-domain-association-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateDomainAssociation for a domain associated with no resource fails with EntityNotFound and the exact
    message "The provided Domain Name is not associated with any Resource.", leaving the target tenant's domains
    and ETag unchanged."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    target_domain = f"{ctx.unique_name('sim2real-cf-tgt-')}.sim2real-behav-checks.click"
    target_id, target_etag = _create_tenant(ctx, dist_id, target_domain, enabled=False)

    unregistered_domain = f"{ctx.unique_name('sim2real-cf-unregistered-')}.sim2real-behav-checks.click"
    code, message = _error(
        lambda: cf.update_domain_association(
            Domain=unregistered_domain, TargetResource={"DistributionTenantId": target_id}, IfMatch=target_etag
        )
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code!r}"
    expected_message = "The provided Domain Name is not associated with any Resource."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the target tenant's domains and version are untouched.
    after = cf.get_distribution_tenant(Identifier=target_id)
    domains = [d["Domain"] for d in after["DistributionTenant"]["Domains"]]
    assert unregistered_domain not in domains, (
        f"rejected call still associated {unregistered_domain!r} with the target tenant: {domains!r}"
    )
    assert after["ETag"] == target_etag, (
        f"target tenant version changed after a rejected call: expected {target_etag!r}, got {after['ETag']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). A success raises: accepting input AWS refuses
    is a finding in itself, not a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _multi_tenant_origin_config() -> dict:
    return {
        "Id": "origin1",
        "DomainName": "www.example.com",
        "CustomOriginConfig": {
            "HTTPPort": 80,
            "HTTPSPort": 443,
            "OriginProtocolPolicy": "https-only",
            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
            "OriginReadTimeout": 30,
            "OriginKeepaliveTimeout": 5,
        },
    }


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    config = {
        "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
        "Comment": "sim2real update-domain-association-not-found-rejected",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "Origins": {"Quantity": 1, "Items": [_multi_tenant_origin_config()]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _teardown_distribution(ctx, dist_id))
    return dist_id


def _create_tenant(ctx, dist_id: str, domain: str, enabled: bool):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=name,
        Domains=[{"Domain": domain}],
        Enabled=enabled,
        # We don't own `domain`, so the managed certificate this requests sits in pending
        # validation forever — but CreateDistributionTenant, the contract under test,
        # succeeds either way. ValidationTokenHost="self-hosted" avoids CloudFront
        # synchronously demanding that the domain's DNS already CNAME to it, which
        # ValidationTokenHost="cloudfront" does.
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "CertificateTransparencyLoggingPreference": "disabled",
            "PrimaryDomainName": domain,
        },
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(ctx, tenant_id))
    return tenant_id, resp["ETag"]


def _wait_tenant_deployed(ctx, tenant_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0) -> str:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
        if resp["DistributionTenant"]["Status"] == "Deployed":
            return resp["ETag"]
        time.sleep(interval_s)
    raise AssertionError(f"tenant {tenant_id} never reached Deployed within {timeout_s}s")


def _delete_tenant(ctx, tenant_id: str) -> None:
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        current = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    etag = current["ETag"]
    # DeleteDistributionTenant refuses (ResourceNotDisabled) while the tenant is enabled.
    if current["DistributionTenant"].get("Enabled"):
        etag = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)["ETag"]
    etag = _wait_tenant_deployed(ctx, tenant_id)
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _wait_distribution_deployed(ctx, dist_id: str, timeout_s: float = 1500.0, interval_s: float = 15.0):
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")


def _teardown_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    config = cfg["DistributionConfig"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    resp = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

