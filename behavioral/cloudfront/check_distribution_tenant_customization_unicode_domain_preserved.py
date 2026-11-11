"""distribution-tenant-customization-unicode-domain-preserved."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "distribution-tenant-customization-unicode-domain-preserved"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tenant's punycode (ACE) IDN domain and multi-byte Unicode Parameter value round-trip
    through GetDistributionTenant unchanged: CloudFront neither re-encodes an ACE label nor
    mangles non-ASCII Parameter bytes."""
    cf = ctx.client("cloudfront")
    param_definitions = [
        {
            "Name": "greeting",
            "Definition": {
                "StringSchema": {
                    "Comment": "unicode greeting used to render tenant-specific content",
                    "DefaultValue": "hello",
                    "Required": False,
                }
            },
        }
    ]
    dist_id = _create_multi_tenant_distribution(ctx, parameter_definitions=param_definitions)
    cg_id = _create_connection_group(ctx)

    unique_ascii = ctx.unique_name("").replace("_", "").replace("-", "")[:8].lower()
    unicode_label = f"caf\u00e9{unique_ascii}"  # "café<suffix>" -- requires punycode
    punycode_domain = f"{unicode_label}.sim2real-cftest.net".encode("idna").decode("ascii")
    unicode_value = "Bienvenue \u2615 \u65e5\u672c\u8a9e \U0001F389"  # coffee/CJK/emoji

    tenant_id = _create_distribution_tenant(
        ctx,
        dist_id,
        punycode_domain,
        connection_group_id=cg_id,
        parameters=[{"Name": "greeting", "Value": unicode_value}],
    )

    tenant = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]

    assert len(tenant["Domains"]) == 1, (
        f"expected exactly 1 domain on the tenant, got {tenant['Domains']!r}"
    )
    assert tenant["Domains"][0]["Domain"] == punycode_domain, (
        f"expected domain {punycode_domain!r} to round-trip unchanged, got "
        f"{tenant['Domains'][0]['Domain']!r}"
    )
    params_by_name = {p["Name"]: p["Value"] for p in tenant.get("Parameters", [])}
    assert params_by_name.get("greeting") == unicode_value, (
        f"expected Unicode Parameter value {unicode_value!r} to round-trip unchanged, got "
        f"{params_by_name.get('greeting')!r}"
    )

    # The slow deletes run here, in dependency order; the on_cleanup each helper registers is an
    # idempotent backstop if the body raises before reaching here.
    _delete_distribution_tenant(ctx, tenant_id)
    _delete_connection_group(ctx, cg_id)
    _delete_distribution(ctx, dist_id)


# ===== helpers =====

def _create_multi_tenant_distribution(ctx, parameter_definitions=None):
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-cf-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "sim2real multi-tenant unicode test distribution",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": parameter_definitions or []},
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
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        }
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id, timeout_s=1200, interval_s=15):
    cf = ctx.client("cloudfront")
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:  # already deleted by an earlier call in this run
        if exc.response["Error"]["Code"] != "NoSuchDistribution":
            raise
        return
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
        Name=name, Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    cg_id = resp["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, cg_id))
    return cg_id


def _delete_connection_group(ctx, cg_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    try:
        g = cf.get_connection_group(Identifier=cg_id)
    except ClientError as exc:  # already deleted by an earlier call in this run
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
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


def _create_distribution_tenant(ctx, distribution_id, domain, connection_group_id=None, parameters=None):
    # CreateDistributionTenant requires a certificate somewhere ("There must be at least one
    # certificate in the distribution tenant or distribution, or there must be a managed
    # certificate request"), and a ManagedCertificateRequest with
    # ValidationTokenHost=cloudfront makes CloudFront verify domain ownership before issuing
    # it -- which CloudFront rejects for a domain whose DNS the caller does not control
    # (InvalidArgument: "Could not verify Domain Name ownership"). ValidationTokenHost=self-hosted defers
    # that DNS-pointing requirement to whenever the caller chooses to serve the token -- never,
    # here -- which satisfies the certificate requirement at create time without needing this
    # domain to resolve to anything real. The check only asserts Domain/Parameter
    # representation, never TLS serving, so a certificate that never finishes validating is fine.
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-tenant-")
    kwargs = {
        "DistributionId": distribution_id,
        "Name": name,
        "Domains": [{"Domain": domain}],
        "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
        "ManagedCertificateRequest": {
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domain,
        },
    }
    if connection_group_id:
        kwargs["ConnectionGroupId"] = connection_group_id
    if parameters:
        kwargs["Parameters"] = parameters
    resp = cf.create_distribution_tenant(**kwargs)
    tenant_id = resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution_tenant(ctx, tenant_id))
    return tenant_id


def _delete_distribution_tenant(ctx, tenant_id, timeout_s=600, interval_s=10):
    cf = ctx.client("cloudfront")
    try:
        t = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:  # already deleted by an earlier call in this run
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
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
