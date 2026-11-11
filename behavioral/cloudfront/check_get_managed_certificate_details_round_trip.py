"""get-managed-certificate-details-round-trip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-managed-certificate-details-round-trip"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


def _poll_until(probe, predicate, timeout_s=1800.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _wait_distribution_deployed(ctx, dist_id, timeout_s=1800.0, interval_s=15.0):
    cf = ctx.client("cloudfront")
    resp = _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return resp["ETag"]


def _create_multi_tenant_distribution(ctx):
    """Create a minimal tenant-only (multi-tenant) distribution.

    Must be created Enabled=True: CreateDistributionTenant against a disabled
    multi-tenant distribution is rejected with InvalidAssociation, so cleanup
    disables it before delete.
    """
    cf = ctx.client("cloudfront")
    origin_domain = f"{ctx.unique_name('sim2real-cf-origin-')}.s3.us-east-1.amazonaws.com"
    resp = cf.create_distribution(
        DistributionConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-mt-"),
            "Comment": "sim2real behavioral check multi-tenant distribution",
            "Enabled": True,
            "ConnectionMode": "tenant-only",
            "TenantConfig": {
                "ParameterDefinitions": [
                    {
                        "Name": "tenantName",
                        "Definition": {
                            "StringSchema": {
                                "Comment": "tenant name",
                                "DefaultValue": "root",
                                "Required": False,
                            }
                        },
                    }
                ]
            },
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": "primary-origin",
                        "DomainName": origin_domain,
                        "OriginPath": "/{{tenantName}}",
                        "S3OriginConfig": {"OriginAccessIdentity": ""},
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": "primary-origin",
                "ViewerProtocolPolicy": "allow-all",
                "CachePolicyId": "658327ea-f89d-4fab-a63d-7e88639e58f6",
            },
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id):
    cf = ctx.client("cloudfront")
    etag = _wait_distribution_deployed(ctx, dist_id)
    cfg = cf.get_distribution_config(Id=dist_id)
    if cfg["DistributionConfig"].get("Enabled"):
        dcfg = cfg["DistributionConfig"]
        dcfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=dcfg, IfMatch=cfg["ETag"])
        etag = _wait_distribution_deployed(ctx, dist_id)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_connection_group(ctx):
    cf = ctx.client("cloudfront")
    resp = cf.create_connection_group(Name=ctx.unique_name("sim2real-cf-cg-"))
    cg_id = resp["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, cg_id))
    return cg_id


def _delete_connection_group(ctx, cg_id, timeout_s=600.0, interval_s=10.0):
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


def _delete_distribution_tenant(ctx, tenant_id):
    cf = ctx.client("cloudfront")
    try:
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=resp["ETag"])


def _create_distribution_tenant(ctx, distribution_id, domain, **extra):
    cf = ctx.client("cloudfront")
    kwargs = {
        "DistributionId": distribution_id,
        "Name": ctx.unique_name("sim2real-cf-tenant-"),
        "Domains": [{"Domain": domain}],
        "Enabled": False,
    }
    kwargs.update(extra)
    resp = cf.create_distribution_tenant(**kwargs)
    tenant = resp["DistributionTenant"]
    ctx.on_cleanup(lambda tid=tenant["Id"]: _delete_distribution_tenant(ctx, tid))
    return tenant


def _expect_error(fn):
    """Run fn and return (code, message) from the ClientError it must raise.

    Raises if fn unexpectedly succeeds, so a target that accepts the call fails as an
    accepted call, not as a silent pass.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetManagedCertificateDetails on a self-hosted-validation tenant returns its pending-validation ACM
    certificate, while CreateDistributionTenant with ValidationTokenHost "cloudfront" for a domain not
    resolving to CloudFront is refused with InvalidArgument and the exact message and creates no tenant."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multi_tenant_distribution(ctx)
    cg_id = _create_connection_group(ctx)

    control_domain = f"{ctx.unique_name('sim2real-cf-ctrl-').strip('-')}.sim2real-cftest.net"
    control = _create_distribution_tenant(
        ctx,
        dist_id,
        control_domain,
        ConnectionGroupId=cg_id,
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": control_domain},
    )
    assert control["Domains"][0]["Domain"] == control_domain, (
        f"expected the self-hosted-validation positive control tenant for {control_domain!r}, "
        f"got domains {control['Domains']!r}"
    )

    # Round trip: the control tenant's managed certificate request reads back as a pending ACM
    # certificate (CloudFront certificates live in us-east-1) with the requested token host.
    details = cf.get_managed_certificate_details(Identifier=control["Id"])["ManagedCertificateDetails"]
    assert details["CertificateArn"].startswith("arn:aws:acm:us-east-1:"), (
        f"expected a us-east-1 ACM certificate ARN, got {details['CertificateArn']!r}"
    )
    assert details["ValidationTokenHost"] == "self-hosted", details.get("ValidationTokenHost")
    assert details["CertificateStatus"] == "pending-validation", (
        f"expected the never-validated certificate to be pending-validation, got {details['CertificateStatus']!r}"
    )

    # Break exactly one thing: request cloudfront-hosted validation for a domain whose DNS
    # the caller does not control.
    domain = f"{ctx.unique_name('sim2real-cf-cert-').strip('-')}.sim2real-cftest.net"
    code, message = _expect_error(
        lambda: cf.create_distribution_tenant(
            DistributionId=dist_id,
            Name=ctx.unique_name("sim2real-cf-tenant-"),
            Domains=[{"Domain": domain}],
            ConnectionGroupId=cg_id,
            Enabled=False,
            ManagedCertificateRequest={
                "ValidationTokenHost": "cloudfront",
                "PrimaryDomainName": domain,
                "CertificateTransparencyLoggingPreference": "disabled",
            },
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument, got {code!r} ({message!r})"
    assert message == (
        "The provided Domain Name is not valid. Could not verify Domain Name ownership. "
        "It may not be pointing to a valid CloudFront resource."
    ), f"expected AWS's exact domain-ownership refusal, got {message!r}"

    # Effect absent: the refused domain has no tenant, via an independent read.
    absent_code, absent_message = _expect_error(
        lambda: cf.get_distribution_tenant_by_domain(Domain=domain)
    )
    assert absent_code == "EntityNotFound", (
        f"expected EntityNotFound for the refused domain {domain!r}, got {absent_code!r}"
    )
    assert absent_message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact not-found message for the refused domain, got {absent_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
