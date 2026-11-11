"""associate-distribution-tenant-web-acl-nonexistent-tenant-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-distribution-tenant-web-acl-nonexistent-tenant-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

#: A never-issued distribution-tenant id: "dt_" and 27 alphanumerics, the shape CloudFront issues.
_NEVER_ISSUED_TENANT_ID = "dt_3Sim2RealNeverIssuedTenant0"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionTenantWebACL against a distribution-tenant id that was never
    created returns EntityNotFound, while the same call against a real tenant (the positive
    control) succeeds and is unaffected by the rejected call."""
    cf = ctx.client("cloudfront")

    # The web ACL is created first so its cleanup runs after the tenant's and distribution's
    # (LIFO): WAF refuses to delete a web ACL that a CloudFront resource still references.
    web_acl_arn = _create_cloudfront_web_acl(ctx)
    dist_id = _create_multi_tenant_distribution(ctx)
    tenant_name = ctx.unique_name("sim2real-tenant-")
    domain = _domain_name(ctx, "tenant")
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=tenant_name,
        Domains=[{"Domain": domain}],
        Enabled=False,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
            "CertificateTransparencyLoggingPreference": "disabled",
        },
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    real_tenant_id = tenant_resp["DistributionTenant"]["Id"]
    real_tenant_etag = tenant_resp["ETag"]
    ctx.on_cleanup(lambda: cf.delete_distribution_tenant(
        Id=real_tenant_id, IfMatch=cf.get_distribution_tenant(Identifier=real_tenant_id)["ETag"]
    ))

    # A fixed id of a real tenant id's shape, so it clears CloudFront's format check on Id and
    # reaches the not-found lookup. IfMatch must also be present and well-formed -- omitting it
    # surfaces InvalidIfMatchVersion ahead of the not-found check.
    fake_tenant_id = _NEVER_ISSUED_TENANT_ID
    code, msg = _error(lambda: cf.associate_distribution_tenant_web_acl(
        Id=fake_tenant_id, WebACLArn=web_acl_arn, IfMatch=real_tenant_etag
    ))
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code!r}"
    assoc_msg = "The specified distribution tenant doesn't exist."
    assert msg == assoc_msg, f"expected message {assoc_msg!r}, got {msg!r}"

    # Effect absent: the never-created tenant still doesn't exist.
    not_found_code, not_found_msg = _error(lambda: cf.get_distribution_tenant(Identifier=fake_tenant_id))
    assert not_found_code == "EntityNotFound", f"expected EntityNotFound, got {not_found_code!r}"
    get_msg = "The specified distribution tenant doesn't exist."
    assert not_found_msg == get_msg, (
        f"expected message {get_msg!r}, got {not_found_msg!r}"
    )

    # Positive control in the same file: the identical call against a real tenant succeeds.
    assoc = cf.associate_distribution_tenant_web_acl(
        Id=real_tenant_id, WebACLArn=web_acl_arn, IfMatch=real_tenant_etag
    )
    assert assoc["WebACLArn"] == web_acl_arn, f"expected {web_acl_arn!r}, got {assoc['WebACLArn']!r}"
    after = cf.get_distribution_tenant(Identifier=real_tenant_id)["DistributionTenant"]
    actual_arn = after["Customizations"]["WebAcl"]["Arn"]
    assert actual_arn == web_acl_arn, f"expected {web_acl_arn!r}, got {actual_arn!r}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _domain_name(ctx, label: str) -> str:
    # CloudFront rejects any *.example.com/.example.org/.example.net domain outright with
    # InvalidArgument ("Domain Name not allowed") -- those roots are IANA-reserved documentation
    # domains and CloudFront denylists them explicitly. A random, unregistered .com name clears
    # the same format/denylist check without requiring us to actually own or DNS-validate it.
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "nonexistent tenant negative check",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": []},
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "origin.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        },
    }
    resp = cf.create_distribution(DistributionConfig=config)
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, dist_id))
    return dist_id


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    config = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if config.get("Enabled"):
        config["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)["ETag"]
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        got = cf.get_distribution(Id=dist_id)
        etag = got["ETag"]
        if got["Distribution"]["Status"] == "Deployed":
            break
        time.sleep(20)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)


def _create_cloudfront_web_acl(ctx) -> str:
    # WAFv2 web ACLs with Scope="CLOUDFRONT" are global but must be managed via the us-east-1
    # endpoint specifically -- any other region rejects with WAFInvalidParameterException.
    waf = ctx.client("wafv2", region="us-east-1")
    name = ctx.unique_name("sim2real-acl-")
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", "")[:128],
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    summary = resp["Summary"]
    acl_id = summary["Id"]
    arn = summary["ARN"]

    def _cleanup():
        got = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id)
        waf.delete_web_acl(Name=name, Scope="CLOUDFRONT", Id=acl_id, LockToken=got["LockToken"])

    ctx.on_cleanup(_cleanup)
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
