"""distribution-tenant-lifecycle."""
from __future__ import annotations

import time
import uuid
from botocore.exceptions import ClientError

from behavioral_harness import tags

# AWS-managed CachePolicy id for "Managed-CachingOptimized".
MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"

# Every CreateDistributionTenant / domain-changing UpdateDistributionTenant needs a
# certificate path, and it must not pin PrimaryDomainName (see the create call for why).
_MANAGED_CERT_REQUEST = {"ValidationTokenHost": "self-hosted"}


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")

def _wait_distribution_deployed(cf, dist_id, timeout_s=1200, interval_s=15, etag_hint=None):
    holder = {"etag": etag_hint}
    def probe():
        resp = cf.get_distribution(Id=dist_id)
        holder["etag"] = resp["ETag"]
        return resp["Distribution"]["Status"]
    _poll_until(probe, lambda status: status == "Deployed", timeout_s=timeout_s, interval_s=interval_s)
    return holder["etag"]

def _wait_distribution_status(cf, dist_id, status, *, timeout_s=240, interval_s=5):
    return _poll_until(
        lambda: cf.get_distribution(Id=dist_id),
        lambda r: r["Distribution"]["Status"] == status,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} reaching status {status}",
    )

def _force_delete_distribution(cf, dist_id):
    cfg_resp = cf.get_distribution_config(Id=dist_id)
    cfg = cfg_resp["DistributionConfig"]
    etag = cfg_resp["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)["ETag"]
    etag = _wait_distribution_deployed(cf, dist_id, etag_hint=etag)
    cf.delete_distribution(Id=dist_id, IfMatch=etag)

def _delete_distribution_tenant(cf, tenant_id):
    try:
        cur = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    if cur["DistributionTenant"].get("Enabled"):
        cur = cf.update_distribution_tenant(
            Id=tenant_id,
            IfMatch=cur["ETag"],
            Enabled=False,
            Domains=[{"Domain": d["Domain"]} for d in cur["DistributionTenant"]["Domains"]],
        )
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=cur["ETag"])

def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]

def _short_unique_name(max_len=32):
    return ("sim2real-behav-" + uuid.uuid4().hex)[:max_len]

def _minimal_multi_tenant_distribution_config(name):
    origin_domain = f"{name}.s3.amazonaws.com"
    return {
        "CallerReference": name,
        "Comment": name,
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
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "OriginPath": "/{{tenantName}}",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": MANAGED_CACHING_OPTIMIZED_CACHE_POLICY_ID,
        },
    }

def _create_multi_tenant_distribution_and_tenant(cf, ctx, prefix="sim2real-behav-mtd-"):
    """Create a multi-tenant Distribution + one DistributionTenant on it.
    Returns ``(dist_id, tenant_id, tenant_domain)``; both are registered for cleanup."""
    name = ctx.unique_name(prefix)
    create_resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": _minimal_multi_tenant_distribution_config(name),
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist_id = create_resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    # Bounded so a slow multi-tenant deploy fails cleanly instead of running past the check ceiling.
    try:
        _wait_distribution_status(cf, dist_id, "Deployed", timeout_s=240, interval_s=5)
    except AssertionError as exc:
        raise AssertionError(
            f"multi-tenant distribution did not reach Deployed within the "
            f"per-check budget: {exc}",
        ) from exc

    tenant_name = _short_unique_name(28)
    domain = f"{tenant_name}.sim2real.test"
    dt_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=tenant_name,
        Domains=[{"Domain": domain}],
        Enabled=True,
        # "self-hosted" defers ownership verification of a domain we don't own ("cloudfront"
        # rejects it with InvalidArgument). PrimaryDomainName is omitted: pinning it makes the
        # later domain swap fail with InvalidArgument.
        ManagedCertificateRequest=_MANAGED_CERT_REQUEST,
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    tenant_id = dt_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_tenant(cf, tenant_id))
    return dist_id, tenant_id, domain

CHECK = "distribution-tenant-lifecycle"
GROUP = 'distribution-tenant'
SERVICES = ['cloudfront']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DistributionTenant lifecycle: create, get, by-domain lookup is EntityNotFound (cert pending),
    list, swap domain then disable in separate requests (ETag rotates each time), delete, and
    get/delete on the dead id fail EntityNotFound."""
    cf = ctx.client("cloudfront")
    dist_id, tenant_id, domain = _create_multi_tenant_distribution_and_tenant(cf, ctx, prefix="sim2real-behav-dtlc-")

    get_resp = cf.get_distribution_tenant(Identifier=tenant_id)
    tenant_etag = get_resp["ETag"]
    assert get_resp["DistributionTenant"]["DistributionId"] == dist_id
    assert get_resp["DistributionTenant"]["Domains"][0]["Domain"] == domain

    # A domain only resolves once its certificate is validated, which needs domain ownership; the
    # get above rules out "tenant never created" as the reason for EntityNotFound.
    by_domain_code, by_domain_message = _error(
        lambda: cf.get_distribution_tenant_by_domain(Domain=domain)
    )
    assert by_domain_code == "EntityNotFound", (
        f"expected GetDistributionTenantByDomain to report EntityNotFound for a domain whose "
        f"managed certificate is still pending validation, got {by_domain_code!r}"
    )
    assert by_domain_message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {by_domain_message!r}"
    )

    listed = cf.list_distribution_tenants()
    ids = [t["Id"] for t in listed["DistributionTenantList"]]
    assert tenant_id in ids, f"expected {tenant_id} in ListDistributionTenants, got {ids}"

    account = _account_id(ctx)
    bogus_webacl_arn = (
        f"arn:aws:wafv2:{ctx.region}:{account}:global/webacl/"
        f"{ctx.unique_name('sim2real-behav-noassoc-')}/00000000-0000-0000-0000-000000000000"
    )
    by_customization = cf.list_distribution_tenants_by_customization(WebACLArn=bogus_webacl_arn)
    cust_ids = [t["Id"] for t in by_customization["DistributionTenantList"]]
    assert tenant_id not in cust_ids, (
        "a tenant with no WebACL customization must not show up filtered by an "
        f"unrelated WebACLArn, got {cust_ids}"
    )

    # Real AWS refuses a combined disable-and-modify ("You can't disable and update a
    # distribution tenant in the same request"), so the two beats are two requests, each
    # chained on the ETag the previous one returned.
    updated_domain = f"upd-{domain}"
    update_resp = cf.update_distribution_tenant(
        Id=tenant_id,
        IfMatch=tenant_etag,
        DistributionId=dist_id,
        Domains=[{"Domain": updated_domain}],
        ManagedCertificateRequest=_MANAGED_CERT_REQUEST,
    )
    updated_tenant = update_resp["DistributionTenant"]
    updated_etag = update_resp["ETag"]
    assert updated_tenant["Domains"][0]["Domain"] == updated_domain, (
        f"expected the swapped domain {updated_domain!r}, got {updated_tenant['Domains']!r}"
    )
    assert updated_etag != tenant_etag, "ETag must rotate after a successful update"

    disable_resp = cf.update_distribution_tenant(Id=tenant_id, IfMatch=updated_etag, Enabled=False)
    disabled_tenant = disable_resp["DistributionTenant"]
    assert disabled_tenant["Enabled"] is False, (
        f"expected Enabled=False after the disabling update, got {disabled_tenant['Enabled']!r}"
    )
    assert disable_resp["ETag"] != updated_etag, "ETag must rotate again after the disabling update"
    assert disabled_tenant["Domains"][0]["Domain"] == updated_domain, (
        f"expected the disabling update to preserve the swapped domain {updated_domain!r}, "
        f"got {disabled_tenant['Domains']!r}"
    )

    final_tenant = cf.get_distribution_tenant(Identifier=tenant_id)
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=final_tenant["ETag"])

    code, message = _error(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    assert code == "EntityNotFound", f"expected EntityNotFound after delete, got {code}"
    assert message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {message!r}"
    )

    dead_delete_code, dead_delete_message = _error(
        lambda: cf.delete_distribution_tenant(Id=tenant_id, IfMatch=final_tenant["ETag"])
    )
    assert dead_delete_code == "EntityNotFound", (
        f"expected a mutation on the deleted tenant to also fail with EntityNotFound, "
        f"got {dead_delete_code}"
    )
    assert dead_delete_message == "The specified distribution tenant doesn't exist.", (
        f"expected AWS's exact message, got {dead_delete_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
