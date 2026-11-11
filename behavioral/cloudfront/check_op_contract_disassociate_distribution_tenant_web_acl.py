"""op-contract-disassociateDistributionTenantWebACL."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disassociateDistributionTenantWebACL"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DisassociateDistributionTenantWebACL rejects a malformed tenant Id (InvalidArgument) and a
    bogus IfMatch (InvalidIfMatchVersion), and with a real tenant's current ETag is an idempotent
    no-op while no web ACL is attached."""
    cf = ctx.client("cloudfront")
    if not (
        hasattr(cf, "disassociate_distribution_tenant_web_acl")
        and hasattr(cf, "create_distribution_tenant")
    ):
        raise AssertionError(
            "unreachable: distribution-tenant operations not present in installed botocore"
        )

    # The op's identifier boundary is exercisable without any multi-tenant distribution: an
    # Id that is not in tenant-Id form is refused as InvalidArgument before any lookup.
    bogus_id = "TDOESNOTEXIST0000000"
    code, msg = _error(
        lambda: cf.disassociate_distribution_tenant_web_acl(
            Id=bogus_id, IfMatch="E000000000FAKEBOGUS"
        )
    )
    assert code == "InvalidArgument", f"expected InvalidArgument for a malformed tenant Id, got {code}"
    assert msg == "Id format is invalid", f"unexpected message for a malformed tenant Id: {msg!r}"

    # Success path: a multi-tenant distribution, a connection group and a tenant bound to a
    # domain under a non-reserved root (IANA-reserved roots such as example.com are rejected
    # as "Domain Name not allowed"), with certificate validation deferred to "self-hosted".
    dist_id = _create_multitenant_distribution(ctx)
    cg_id = _create_connection_group(ctx)
    domain = ctx.unique_name("sim2real-tdt-").replace("_", "-") + ".sim2real-cftest.net"
    tenant_id = _create_tenant(ctx, dist_id, domain, cg_id)
    tenant_etag = cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]

    result = cf.disassociate_distribution_tenant_web_acl(Id=tenant_id, IfMatch=tenant_etag)
    assert result["Id"] == tenant_id

    code2, msg2 = _error(
        lambda: cf.disassociate_distribution_tenant_web_acl(
            Id=tenant_id, IfMatch="E000000000FAKEBOGUS"
        )
    )
    assert code2 == "InvalidIfMatchVersion", f"expected InvalidIfMatchVersion for a bogus IfMatch, got {code2}"
    assert msg2 == "The If-Match version is missing or not valid for the resource.", (
        f"unexpected message for a bogus IfMatch: {msg2!r}"
    )


# ===== helpers =====
def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_multitenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    origin_id = "sim2real-origin"
    config = {
        "CallerReference": ctx.unique_name("sim2real-tdt-dist-"),
        "Comment": "sim2real behavioral check (multi-tenant)",
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
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id


def _wait_deployed(get, key: str, timeout_s: float):
    """Poll get() until resp[key]["Status"] is Deployed; return that response, or the last
    one read when the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        resp = get()
        if resp[key]["Status"] == "Deployed" or time.monotonic() >= deadline:
            return resp
        time.sleep(2)


def _delete_distribution(cf, dist_id) -> None:
    try:
        _wait_deployed(lambda: cf.get_distribution(Id=dist_id), "Distribution", 900)
        cfg = cf.get_distribution_config(Id=dist_id)
        etag = cfg["ETag"]
        if cfg["DistributionConfig"].get("Enabled"):
            config = cfg["DistributionConfig"]
            config["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=etag)
            etag = _wait_deployed(lambda: cf.get_distribution(Id=dist_id), "Distribution", 900)["ETag"]
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
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


def _create_connection_group(ctx) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_connection_group(
        Name=ctx.unique_name("sim2real-tdt-cg-"),
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
    )
    cg_id = resp["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(cf, cg_id))
    return cg_id


def _delete_connection_group(cf, cg_id) -> None:
    try:
        g = cf.get_connection_group(Identifier=cg_id)
        etag = g["ETag"]
        if g["ConnectionGroup"].get("Enabled", True):
            etag = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)["ETag"]
        etag = _wait_deployed(lambda: cf.get_connection_group(Identifier=cg_id), "ConnectionGroup", 600)["ETag"]
        cf.delete_connection_group(Id=cg_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _create_tenant(ctx, dist_id, domain, cg_id) -> str:
    cf = ctx.client("cloudfront")
    tenant = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tdt-tenant-"),
        Domains=[{"Domain": domain}],
        ConnectionGroupId=cg_id,
        Enabled=True,
        Tags={"Items": [{"Key": "sim2real", "Value": CHECK}]},
        # The check does not own the domain: "self-hosted" defers ownership verification
        # (certificate left pending validation) so the create succeeds.
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
    )["DistributionTenant"]
    tenant_id = tenant["Id"]
    ctx.on_cleanup(lambda: _delete_tenant(cf, tenant_id))
    return tenant_id


def _delete_tenant(cf, tenant_id) -> None:
    try:
        current = cf.get_distribution_tenant(Identifier=tenant_id)
        etag = current["ETag"]
        if current["DistributionTenant"].get("Enabled"):
            etag = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)["ETag"]
        etag = _wait_deployed(lambda: cf.get_distribution_tenant(Identifier=tenant_id), "DistributionTenant", 600)["ETag"]
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
