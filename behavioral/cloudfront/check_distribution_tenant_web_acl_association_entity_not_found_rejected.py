"""distribution-tenant-web-acl-association-entity-not-found-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "distribution-tenant-web-acl-association-entity-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionTenantWebACL and GetDistributionTenant on a well-formed but never-issued tenant
    id fail with EntityNotFound and the exact message, while the same association on a real tenant
    succeeds and GetDistributionTenant shows the web ACL."""
    cf = ctx.client("cloudfront")
    web_acl = _create_web_acl(ctx)

    # Create a real distribution tenant FIRST so the negative case below can
    # mimic its exact ID shape (AWS-generated, fixed-length uppercase
    # alphanumeric) -- a free-form "nonexistent-..." string instead fails
    # FORMAT validation with InvalidArgument before CloudFront ever looks the
    # id up, masking the EntityNotFound this check is after.
    tenant_dist_config = _minimal_distribution_config(
        caller_reference=ctx.unique_name("sim2real-tenantwebacl-mt-"),
        comment="sim2real multi-tenant distribution for tenant web-acl check",
        extra={"ConnectionMode": "tenant-only", "TenantConfig": {"ParameterDefinitions": []}},
    )
    tenant_dist = cf.create_distribution(DistributionConfig=tenant_dist_config)["Distribution"]
    tenant_dist_id = tenant_dist["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution(ctx, tenant_dist_id))

    domain = _domain_name(ctx, "tenantacl")
    tenant_name = ctx.unique_name("sim2real-tenant-").rstrip("-") + "0"
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=tenant_dist_id,
        Name=tenant_name,
        Domains=[{"Domain": domain}],
        Enabled=True,
        ManagedCertificateRequest={
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
            "CertificateTransparencyLoggingPreference": "disabled",
        },
    )
    tenant = tenant_resp["DistributionTenant"]
    tenant_id = tenant["Id"]
    tenant_etag = tenant_resp["ETag"]
    ctx.on_cleanup(lambda: _disable_and_delete_distribution_tenant(ctx, tenant_id))

    # Same shape (length + character set) as the real tenant id above, but a
    # freshly-random value that was never issued -- well-formed enough to pass
    # CloudFront's format check and actually reach the EntityNotFound lookup.
    bogus_tenant_id = _same_shape_random_id(tenant_id)
    assert bogus_tenant_id != tenant_id, (bogus_tenant_id, tenant_id)
    # IfMatch is modelled as optional, but CloudFront refuses a call without it with
    # InvalidIfMatchVersion before it looks up the id; the real tenant's well-formed ETag passes
    # that check, so the request reaches the id lookup.
    err = _client_error(
        lambda: cf.associate_distribution_tenant_web_acl(
            Id=bogus_tenant_id, WebACLArn=web_acl["arn"], IfMatch=tenant_etag
        )
    )
    assert err["Code"] == "EntityNotFound", err
    expected = "The specified distribution tenant doesn't exist."
    assert err.get("Message") == expected, (
        f"AssociateDistributionTenantWebACL message {err.get('Message')!r}, expected {expected!r}"
    )

    not_found = _client_error(lambda: cf.get_distribution_tenant(Identifier=bogus_tenant_id))
    assert not_found["Code"] == "EntityNotFound", not_found
    expected = "The specified distribution tenant doesn't exist."
    assert not_found.get("Message") == expected, (
        f"GetDistributionTenant message {not_found.get('Message')!r}, expected {expected!r}"
    )

    # Positive control: the identical operation, same file, against the REAL
    # tenant id succeeds and is reflected on GetDistributionTenant.
    assoc = cf.associate_distribution_tenant_web_acl(
        Id=tenant_id, WebACLArn=web_acl["arn"], IfMatch=tenant_etag
    )
    assert assoc["WebACLArn"] == web_acl["arn"], assoc["WebACLArn"]

    refreshed = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    customization_acl = (refreshed.get("Customizations") or {}).get("WebAcl") or {}
    assert customization_acl.get("Arn") == web_acl["arn"], customization_acl


def _client_error(fn) -> dict:
    """The botocore Error dict of a call expected to fail; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _same_shape_random_id(real_id: str) -> str:
    """A random id with the exact same length and character-class shape
    (upper/lower/digit) as ``real_id`` at every position, but a value that
    was (with overwhelming probability) never issued -- passes CloudFront's
    id FORMAT validation the way a `nonexistent-...`-style free-form string
    doesn't, while still being guaranteed distinct from the real id."""
    import random
    import string

    def _same_class_char(ch: str) -> str:
        if ch.isupper():
            return random.choice(string.ascii_uppercase)
        if ch.islower():
            return random.choice(string.ascii_lowercase)
        if ch.isdigit():
            return random.choice(string.digits)
        return ch

    for _ in range(10):
        candidate = "".join(_same_class_char(ch) for ch in real_id)
        if candidate != real_id:
            return candidate
    raise AssertionError(f"could not derive a distinct same-shape id from {real_id!r}")


def _domain_name(ctx, label: str) -> str:
    # NOTE: CloudFront rejects any *.example.com/.example.org/.example.net domain
    # outright with InvalidArgument ("Domain Name not allowed") -- those roots are
    # IANA-reserved documentation domains and CloudFront denylists them explicitly.
    # A random, unregistered .com name passes the same format/denylist check
    # without requiring us to actually own or DNS-validate it (CloudFront only
    # validates ownership later, via the pending managed-certificate TXT record).
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _wafv2_cloudfront_client(ctx):
    """WAFv2 web ACLs with Scope="CLOUDFRONT" are global but managed only through the
    us-east-1 endpoint; any other region rejects the scope, so the client pins that region."""
    return ctx.client("wafv2", region="us-east-1")


def _create_web_acl(ctx) -> dict[str, str]:
    waf = _wafv2_cloudfront_client(ctx)
    name = ctx.unique_name("sim2real-cf-tenant-acl-")
    metric_name = "".join(ch for ch in name if ch.isalnum())[:128] or "sim2realcftenantacl"
    resp = waf.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": False,
            "CloudWatchMetricsEnabled": False,
            "MetricName": metric_name,
        },
        Rules=[],
    )
    summary = resp["Summary"]
    web_acl_id = summary["Id"]

    def _cleanup() -> None:
        cur = waf.get_web_acl(Name=name, Scope="CLOUDFRONT", Id=web_acl_id)
        waf.delete_web_acl(
            Name=name, Scope="CLOUDFRONT", Id=web_acl_id, LockToken=cur["LockToken"]
        )

    ctx.on_cleanup(_cleanup)
    return {"arn": summary["ARN"], "id": web_acl_id, "name": name}


def _minimal_distribution_config(
    caller_reference: str, comment: str, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    config: dict[str, Any] = {
        "CallerReference": caller_reference,
        "Comment": comment[:128],
        "Enabled": True,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "primary-origin",
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
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "primary-origin",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
        "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
    }
    if extra:
        config.update(extra)
    return config


def _wait_distribution_status(
    ctx, dist_id: str, target_status: str, timeout_s: float = 1800.0, interval_s: float = 20.0
) -> dict[str, Any]:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    resp: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cf.get_distribution(Id=dist_id)
        last = resp["Distribution"]["Status"]
        if last == target_status:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} never reached {target_status!r} (last={last!r})")


def _disable_and_delete_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
    cfg = cfg_resp["DistributionConfig"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        cf.update_distribution(Id=dist_id, DistributionConfig=cfg, IfMatch=cfg_resp["ETag"])
    resp = _wait_distribution_status(ctx, dist_id, "Deployed")
    cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])


def _wait_distribution_tenant_status(
    ctx, tenant_id: str, target_status: str, timeout_s: float = 1800.0, interval_s: float = 20.0
) -> dict[str, Any]:
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + timeout_s
    last = None
    resp: dict[str, Any] = {}
    while time.monotonic() < deadline:
        resp = cf.get_distribution_tenant(Identifier=tenant_id)
        last = resp["DistributionTenant"]["Status"]
        if last == target_status:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"distribution tenant {tenant_id} never reached {target_status!r} (last={last!r})")


def _disable_and_delete_distribution_tenant(ctx, tenant_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        current = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    tenant = current["DistributionTenant"]
    if tenant.get("Enabled"):
        cf.update_distribution_tenant(Id=tenant_id, IfMatch=current["ETag"], Enabled=False)
    resp = _wait_distribution_tenant_status(ctx, tenant_id, "Deployed")
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=resp["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
