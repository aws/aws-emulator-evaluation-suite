"""disassociate-distribution-tenant-web-acl-no-association-invalid-argument-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "disassociate-distribution-tenant-web-acl-no-association-invalid-argument-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """With no web ACL associated, DisassociateDistributionTenantWebACL is a no-op, not a rejection;
    omitting IfMatch is rejected with InvalidIfMatchVersion. Associating a real WAFv2 web ACL and
    then disassociating it clears Customizations.WebAcl again."""
    cf = ctx.client("cloudfront")
    dist_id = _create_multitenant_distribution(ctx)
    cg_id = _create_connection_group(ctx)
    domain = ctx.unique_name("sim2real-cf-tenant-").replace("_", "-") + ".sim2real-cftest.net"
    tenant = _create_tenant(ctx, dist_id, domains=[domain], connection_group_id=cg_id)
    tenant_id = tenant["Id"]
    # Runs before the per-resource teardowns: start every disable at once so their
    # deployments overlap instead of queueing inside the cleanup budget.
    ctx.on_cleanup(lambda: _start_disabling(ctx, dist_id, cg_id, tenant_id))

    pre_resp = cf.get_distribution_tenant(Identifier=tenant_id)
    pre = pre_resp["DistributionTenant"]
    etag = pre_resp["ETag"]
    assert pre.get("Customizations", {}).get("WebAcl") is None, (
        f"expected a freshly created tenant to carry no WebAcl customization, got {pre.get('Customizations')!r}"
    )

    # Break exactly one thing: omit the required IfMatch precondition, leaving everything
    # else identical to the call that succeeds immediately below.
    missing_precondition, missing_message = _error(
        lambda: cf.disassociate_distribution_tenant_web_acl(Id=tenant_id)
    )
    assert missing_precondition == "InvalidIfMatchVersion", (
        f"expected InvalidIfMatchVersion when IfMatch is omitted, got {missing_precondition!r}"
    )
    assert missing_message == "The If-Match version is missing or not valid for the resource.", (
        f"unexpected InvalidIfMatchVersion message: {missing_message!r}"
    )

    # Real AWS does not raise InvalidArgument here: with IfMatch and nothing associated the call
    # succeeds with a fresh ETag.
    noop = cf.disassociate_distribution_tenant_web_acl(Id=tenant_id, IfMatch=etag)
    assert noop is not None, "expected a response from a no-op DisassociateDistributionTenantWebACL"

    # effect-absent: still no web ACL customization on the tenant
    still_resp = cf.get_distribution_tenant(Identifier=tenant_id)
    assert still_resp["DistributionTenant"].get("Customizations", {}).get("WebAcl") is None, (
        f"expected no WebAcl customization after the no-op disassociate, "
        f"got {still_resp['DistributionTenant'].get('Customizations')!r}"
    )
    etag = still_resp["ETag"]

    # positive control: associate a real web ACL, then disassociate succeeds
    acl_arn, cleanup_acl = _create_cloudfront_web_acl(ctx)
    ctx.on_cleanup(cleanup_acl)

    assoc = cf.associate_distribution_tenant_web_acl(Id=tenant_id, WebACLArn=acl_arn, IfMatch=etag)
    associated = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert associated["Customizations"]["WebAcl"]["Arn"] == acl_arn, (
        f"expected WebAcl {acl_arn!r} associated, got {associated.get('Customizations')!r}"
    )

    cf.disassociate_distribution_tenant_web_acl(Id=tenant_id, IfMatch=assoc["ETag"])
    cleared = cf.get_distribution_tenant(Identifier=tenant_id)["DistributionTenant"]
    assert cleared.get("Customizations", {}).get("WebAcl") is None, (
        f"expected no WebAcl customization after disassociate, got {cleared.get('Customizations')!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
            "Tags": {
                "Items": [
                    {"Key": "sim2real", "Value": CHECK},
                    {"Key": "sim2real:managed", "Value": "true"},
                ]
            },
        }
    )["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, dist_id))
    return dist_id


def _delete_distribution(ctx, dist_id) -> None:
    cf = ctx.client("cloudfront")

    def _wait_deployed():
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            d = cf.get_distribution(Id=dist_id)
            if d["Distribution"]["Status"] == "Deployed":
                return d["ETag"]
            time.sleep(15)
        return cf.get_distribution(Id=dist_id)["ETag"]

    try:
        cfg = cf.get_distribution_config(Id=dist_id)
        if cfg["DistributionConfig"].get("Enabled"):
            config = cfg["DistributionConfig"]
            config["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=cfg["ETag"])
        etag = _wait_deployed()
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


def _start_disabling(ctx, dist_id, cg_id, tenant_id) -> None:
    """Teardown: issue Enabled=False for the tenant, connection group and distribution
    without waiting; the per-resource teardowns then only wait for Deployed."""
    cf = ctx.client("cloudfront")
    try:
        t = cf.get_distribution_tenant(Identifier=tenant_id)
        if t["DistributionTenant"].get("Enabled"):
            cf.update_distribution_tenant(Id=tenant_id, IfMatch=t["ETag"], Enabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "NoSuchDistribution"):
            raise
    try:
        g = cf.get_connection_group(Identifier=cg_id)
        if g["ConnectionGroup"].get("Enabled", True):
            cf.update_connection_group(Id=cg_id, IfMatch=g["ETag"], Enabled=False)
    except ClientError as exc:
        # A group still used by the tenant refuses Enabled=False (ResourceInUse); its own
        # teardown disables it after the tenant is deleted.
        if exc.response["Error"]["Code"] not in ("EntityNotFound", "ResourceInUse"):
            raise
    try:
        cfg = cf.get_distribution_config(Id=dist_id)
        config = cfg["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=cfg["ETag"])
    except ClientError as exc:
        # A multi-tenant distribution with a tenant still attached refuses Enabled=False
        # (IllegalUpdate); its own teardown disables it after the tenant is deleted.
        if exc.response["Error"]["Code"] not in (
            "IllegalUpdate",
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
        Name=ctx.unique_name("sim2real-cf-cg-"),
        Tags={
            "Items": [
                {"Key": "sim2real", "Value": CHECK},
                {"Key": "sim2real:managed", "Value": "true"},
            ]
        },
    )
    cg_id = resp["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(ctx, cg_id))
    return cg_id


def _delete_connection_group(ctx, cg_id) -> None:
    cf = ctx.client("cloudfront")
    try:
        g = cf.get_connection_group(Identifier=cg_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    etag = g["ETag"]
    if g["ConnectionGroup"].get("Enabled", True):
        try:
            upd = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)
            etag = upd["ETag"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        try:
            g = cf.get_connection_group(Identifier=cg_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        if g["ConnectionGroup"]["Status"] == "Deployed":
            etag = g["ETag"]
            break
        time.sleep(10)
    try:
        cf.delete_connection_group(Id=cg_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise


def _create_tenant(ctx, dist_id, domains, connection_group_id=None, name=None, enabled=True):
    cf = ctx.client("cloudfront")
    kwargs = {
        "DistributionId": dist_id,
        "Name": name or ctx.unique_name("sim2real-cf-tenant-"),
        "Domains": [{"Domain": d} for d in domains],
        "Enabled": enabled,
        "Tags": {"Items": [{"Key": "sim2real", "Value": CHECK}]},
        # We do not own these domains, so ValidationTokenHost="self-hosted" defers
        # domain-ownership verification (certificate left pending validation) and the
        # create succeeds; "cloudfront" verifies ownership synchronously and rejects it.
        "ManagedCertificateRequest": {
            "ValidationTokenHost": "self-hosted",
            "PrimaryDomainName": domains[0],
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
    # Scope="CLOUDFRONT" web ACLs must be managed via the us-east-1 endpoint; any other
    # region rejects them with WAFInvalidParameterException.
    wafv2 = ctx.client("wafv2", region="us-east-1")
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
        Tags=[
            {"Key": "sim2real", "Value": CHECK},
            {"Key": "sim2real:managed", "Value": "true"},
        ],
    )["Summary"]

    def _cleanup():
        # Retry while the disassociation propagates (WAFAssociatedItemException) or a concurrent
        # edit moved the lock token (WAFOptimisticLockException); raise anything else.
        deadline = time.monotonic() + 120
        while True:
            try:
                token = wafv2.get_web_acl(
                    Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"]
                )["LockToken"]
                wafv2.delete_web_acl(
                    Name=summary["Name"], Scope="CLOUDFRONT", Id=summary["Id"], LockToken=token
                )
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "WAFNonexistentItemException":
                    return
                if code not in ("WAFAssociatedItemException", "WAFOptimisticLockException"):
                    raise
                if time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    return summary["ARN"], _cleanup


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
