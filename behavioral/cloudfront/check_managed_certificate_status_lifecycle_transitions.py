"""managed-certificate-status-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "managed-certificate-status-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


def _client_error(fn):
    """Call fn() and return its botocore Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A managed certificate requested with ValidationTokenHost="self-hosted" reaches pending-validation;
    "cloudfront" on an unowned domain is rejected with InvalidArgument and no tenant is created."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    cg_id = _create_connection_group(ctx)

    # Positive control + the guaranteed transition: self-hosted validation defers domain
    # ownership verification, so CreateDistributionTenant succeeds and the certificate starts
    # in pending-validation instead of being rejected outright.
    domain = f"{ctx.unique_name('sim2real-mc-').strip('-')}.sim2real-cftest.net"
    tenant_id = _create_distribution_tenant(
        ctx, dist_id, domain, connection_group_id=cg_id, managed_cert=True
    )

    final_status = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        details = cf.get_managed_certificate_details(Identifier=tenant_id)[
            "ManagedCertificateDetails"
        ]
        status = details.get("CertificateStatus")
        if status:
            final_status = status
            break
        time.sleep(5)

    assert final_status is not None, "managed certificate status never appeared"
    assert final_status == "pending-validation", (
        "expected a freshly requested managed certificate (unvalidated domain) to be "
        f"pending-validation, got {final_status!r}"
    )

    # ValidationTokenHost="cloudfront" synchronously demands verifiable domain ownership, so
    # CreateDistributionTenant is rejected before a tenant or certificate exists. "issued" would
    # need real DNS validation of an owned domain and is not asserted.
    rejected_domain = f"{ctx.unique_name('sim2real-mc-rejected-').strip('-')}.sim2real-cftest.net"
    error = _client_error(
        lambda: cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name("sim2real-tenant-rejected-"),
            Domains=[{"Domain": rejected_domain}],
            ConnectionGroupId=cg_id,
            ManagedCertificateRequest={
                "ValidationTokenHost": "cloudfront",
                "PrimaryDomainName": rejected_domain,
            },
        )
    )
    assert error.get("Code") == "InvalidArgument", (
        f"expected InvalidArgument for an unverifiable cloudfront-hosted domain, got {error!r}"
    )
    expected = (
        "The provided Domain Name is not valid. Could not verify Domain Name ownership. "
        "It may not be pointing to a valid CloudFront resource."
    )
    assert error.get("Message") == expected, (
        f"expected message {expected!r}, got {error.get('Message')!r}"
    )

    # effect absent: the rejected domain never became a retrievable tenant
    lookup_error = _client_error(
        lambda: cf.get_distribution_tenant_by_domain(Domain=rejected_domain)
    )
    assert lookup_error.get("Code") == "EntityNotFound", (
        f"expected the rejected domain to be absent (EntityNotFound), got {lookup_error!r}"
    )
    expected = "The specified distribution tenant doesn't exist."
    assert lookup_error.get("Message") == expected, (
        f"expected message {expected!r}, got {lookup_error.get('Message')!r}"
    )


def _create_multi_tenant_distribution(ctx, parameter_definitions=None):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-mt-")
    tenant_config = {"ParameterDefinitions": parameter_definitions or []}
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real multi-tenant test distribution",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": tenant_config,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "example.com",
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
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id, timeout_s=1200, interval_s=15):
    cf = ctx.client("cloudfront")
    cfg = cf.get_distribution_config(Id=dist_id)
    etag = cfg["ETag"]
    dcfg = cfg["DistributionConfig"]
    if dcfg.get("Enabled"):
        dcfg["Enabled"] = False
        resp = cf.update_distribution(Id=dist_id, DistributionConfig=dcfg, IfMatch=etag)
        etag = resp["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        d = cf.get_distribution(Id=dist_id)
        if d["Distribution"]["Status"] == "Deployed":
            etag = d["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_connection_group(ctx):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    resp = cf.create_connection_group(
        Name=name, Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    cg_id = resp["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, cg_id))
    return cg_id


def _delete_connection_group(ctx, cg_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    g = cf.get_connection_group(Identifier=cg_id)
    etag = g["ETag"]
    if g["ConnectionGroup"].get("Enabled", True):
        resp = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)
        etag = resp["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        g = cf.get_connection_group(Identifier=cg_id)
        if g["ConnectionGroup"]["Status"] == "Deployed":
            etag = g["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


def _create_distribution_tenant(
    ctx, distribution_id, domain, connection_group_id=None, managed_cert=False, parameters=None
):
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    kwargs = {
        "DistributionId": distribution_id,
        "Name": name,
        "Domains": [{"Domain": domain}],
    }
    if connection_group_id:
        kwargs["ConnectionGroupId"] = connection_group_id
    if managed_cert:
        kwargs["ManagedCertificateRequest"] = {
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
        }
    if parameters:
        kwargs["Parameters"] = parameters
    kwargs["Tags"] = {"Items": [{"Key": "sim2real:managed", "Value": "true"}]}
    resp = cf.create_distribution_tenant(**kwargs)
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_tenant(ctx, tenant_id))
    return tenant_id


def _delete_distribution_tenant(ctx, tenant_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    t = cf.get_distribution_tenant(Identifier=tenant_id)
    etag = t["ETag"]
    if t["DistributionTenant"].get("Enabled", True):
        resp = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)
        etag = resp["ETag"]
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        t = cf.get_distribution_tenant(Identifier=tenant_id)
        if t["DistributionTenant"]["Status"] == "Deployed":
            etag = t["ETag"]
            break
        time.sleep(interval_s)
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
