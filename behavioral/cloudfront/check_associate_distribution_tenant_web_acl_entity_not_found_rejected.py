"""associate-distribution-tenant-web-acl-entity-not-found-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-distribution-tenant-web-acl-entity-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateDistributionTenantWebACL on a nonexistent tenant fails with EntityNotFound "The
    specified distribution tenant doesn't exist." and creates nothing; the same call on a real
    tenant succeeds and GetDistributionTenant shows the web ACL as an override."""
    cf = ctx.client("cloudfront")

    # The web ACL is created first so its cleanup runs after the tenant's and distribution's
    # (LIFO): WAF refuses to delete a web ACL that a CloudFront resource still references.
    acl_arn, cleanup_acl = _create_cloudfront_web_acl(ctx)
    ctx.on_cleanup(cleanup_acl)

    dist_id = _create_multitenant_distribution(ctx)
    domain = _domain_name(ctx, "cf-tenant")
    tenant = _create_tenant(ctx, dist_id, domains=[domain])
    tenant_id = tenant["Id"]
    # sanity: it must not have already had an override before we associate
    pre_envelope = cf.get_distribution_tenant(Identifier=tenant_id)
    pre = pre_envelope["DistributionTenant"]
    assert pre.get("Customizations", {}).get("WebAcl") is None

    # CloudFront validates the tenant-id format (InvalidArgument) and the presence of IfMatch
    # (InvalidIfMatchVersion) before the existence lookup, so the bogus id keeps the real id's
    # character-class shape and the call carries a real tenant's current ETag.
    bogus_tenant_id = _same_shape_random_id(tenant_id)
    assert bogus_tenant_id != tenant_id
    code, msg = _error(
        lambda: cf.associate_distribution_tenant_web_acl(
            Id=bogus_tenant_id, WebACLArn=acl_arn, IfMatch=pre_envelope["ETag"]
        )
    )
    assert code == "EntityNotFound", f"expected EntityNotFound, got {code}"
    assoc_msg = "The specified distribution tenant doesn't exist."
    assert msg == assoc_msg, f"expected message {assoc_msg!r}, got {msg!r}"

    # effect absent: the never-created tenant still doesn't exist
    not_found_code, not_found_msg = _error(lambda: cf.get_distribution_tenant(Identifier=bogus_tenant_id))
    assert not_found_code == "EntityNotFound", f"expected EntityNotFound, got {not_found_code}"
    get_msg = "The specified distribution tenant doesn't exist."
    assert not_found_msg == get_msg, (
        f"expected message {get_msg!r}, got {not_found_msg!r}"
    )

    # positive control: the identical operation, same file, against the real tenant succeeds
    resp = cf.associate_distribution_tenant_web_acl(Id=tenant_id, WebACLArn=acl_arn, IfMatch=pre_envelope["ETag"])
    assert resp["WebACLArn"] == acl_arn

    got = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    web_acl = got["Customizations"]["WebAcl"]
    assert web_acl["Arn"] == acl_arn
    assert web_acl["Action"] == "override"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails on that, not on a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _same_shape_random_id(real_id: str) -> str:
    """A random id with the same length and character-class shape (upper/lower/digit) as
    real_id at every position, but a value that was (with overwhelming probability) never
    issued -- clears CloudFront's tenant-id FORMAT validation the way a free-form string
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

    while True:
        candidate = "".join(_same_class_char(c) for c in real_id)
        if candidate != real_id:
            return candidate


def _domain_name(ctx, label: str) -> str:
    # CloudFront denylists *.example.com/.example.org/.example.net outright with
    # InvalidArgument ("Domain Name not allowed") -- those roots are IANA-reserved
    # documentation domains. A random, unregistered .com name clears the same
    # format/denylist check without requiring us to actually own or DNS-validate it
    # (CloudFront only validates ownership later, via the pending managed-cert TXT record).
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


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
            "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
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
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        config = cfg_resp["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=cfg_resp["ETag"])["ETag"]
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
        "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        "ManagedCertificateRequest": {
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domains[0],
            "CertificateTransparencyLoggingPreference": "disabled",
        },
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


def _create_cloudfront_web_acl(ctx):
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-cf-acl-")
    summary = wafv2.create_web_acl(
        Name=name,
        Scope="CLOUDFRONT",
        DefaultAction={"Allow": {}},
        VisibilityConfig={
            "SampledRequestsEnabled": True,
            "CloudWatchMetricsEnabled": True,
            "MetricName": name.replace("-", ""),
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Summary"]

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            got = wafv2.get_web_acl(Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "WAFNonexistentItemException":
                return
            raise
        # The tenant's deletion can take a short while to release its reference to the ACL.
        deadline = time.monotonic() + 300
        while True:
            try:
                wafv2.delete_web_acl(
                    Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"], LockToken=got["LockToken"]
                )
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "WAFAssociatedItemException" or time.monotonic() > deadline:
                    raise
            time.sleep(15)
            got = wafv2.get_web_acl(Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"])

    return summary["ARN"], _cleanup


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
