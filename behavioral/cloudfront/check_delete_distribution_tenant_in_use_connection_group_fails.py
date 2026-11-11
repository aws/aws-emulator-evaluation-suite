"""delete-distribution-tenant-in-use-connection-group-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-distribution-tenant-in-use-connection-group-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDistributionTenant on an Enabled tenant fails with ResourceNotDisabled and its exact
    message, leaving the tenant enabled; once disabled, the same delete succeeds and the tenant
    answers EntityNotFound."""
    cf = ctx.client("cloudfront")

    dist_id = _create_multi_tenant_distribution(ctx)
    cg = _create_connection_group(ctx)
    # Runs after the tenant teardown and before the group and distribution teardowns: start
    # both disables at once so their deployments overlap inside the cleanup budget.
    ctx.on_cleanup(lambda: _start_disabling(ctx, dist_id, cg["Id"]))
    domain = _domain_name(ctx, "tenant")
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-"),
        Domains=[{"Domain": domain}],
        ConnectionGroupId=cg["Id"],
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
        Enabled=True,
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    tenant_id = tenant_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: _delete_tenant_if_present(ctx, tenant_id))

    deployed = _poll_until(
        lambda: cf.get_distribution_tenant(Identifier=tenant_id),
        lambda r: r["DistributionTenant"]["Status"] == "Deployed",
        timeout_s=1800,
        interval_s=20,
    )
    assert deployed["DistributionTenant"]["Enabled"] is True, (
        f"expected the freshly created tenant to be Enabled, got {deployed['DistributionTenant']['Enabled']!r}"
    )
    etag = deployed["ETag"]

    # Negative: the tenant is still enabled and routing -- delete is rejected.
    code, message = _error(lambda: cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag))
    assert code == "ResourceNotDisabled", f"expected ResourceNotDisabled, got {code!r}"
    assert message == "You must disable the distribution tenant before you can delete it.", f"unexpected ResourceNotDisabled message: {message!r}"

    # Effect absent: the tenant still exists and is still enabled.
    still_there = cf.get_distribution_tenant(Identifier=tenant_id)
    assert still_there["DistributionTenant"]["Id"] == tenant_id, (
        f"expected {tenant_id!r} to still exist after the rejected delete, "
        f"got {still_there['DistributionTenant']['Id']!r}"
    )
    assert still_there["DistributionTenant"]["Enabled"] is True, (
        f"expected the tenant to remain Enabled after the rejected delete, "
        f"got {still_there['DistributionTenant']['Enabled']!r}"
    )

    # Positive control: disable the tenant, then the same delete succeeds.
    cf.update_distribution_tenant(
        Id=tenant_id, Enabled=False, IfMatch=still_there["ETag"]
    )
    disabled = _poll_until(
        lambda: cf.get_distribution_tenant(Identifier=tenant_id),
        lambda r: r["DistributionTenant"]["Status"] == "Deployed" and not r["DistributionTenant"]["Enabled"],
        timeout_s=1800,
        interval_s=20,
    )
    assert disabled["DistributionTenant"]["Enabled"] is False, (
        f"expected the tenant to have deployed Disabled, got {disabled['DistributionTenant']['Enabled']!r}"
    )
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=disabled["ETag"])
    gone_code, gone_message = _error(lambda: cf.get_distribution_tenant(Identifier=tenant_id))
    assert gone_code == "EntityNotFound", f"expected EntityNotFound, got {gone_code!r}"
    assert gone_message == "The specified distribution tenant doesn't exist.", f"unexpected EntityNotFound message: {gone_message!r}"


def _domain_name(ctx, label: str) -> str:
    # CloudFront denylists *.example.com/.example.org/.example.net (IANA-reserved
    # documentation domains) outright with InvalidArgument ("Domain Name not allowed").
    # A random, unregistered .com name passes the same format/denylist check without
    # requiring us to actually own or DNS-validate it (CloudFront only validates
    # ownership later, via the pending managed-certificate TXT record).
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails on that, not on a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {value!r}")


def _delete_tenant_if_present(ctx, tenant_id: str) -> None:
    """Teardown: the positive control normally deletes the tenant already; tolerate that,
    and disable a tenant left enabled by a failed run before deleting it."""
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        got = cf.get_distribution_tenant(Identifier=tenant_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    etag = got["ETag"]
    if got["DistributionTenant"].get("Enabled"):
        etag = cf.update_distribution_tenant(Id=tenant_id, IfMatch=etag, Enabled=False)["ETag"]
        etag = _poll_until(
            lambda: cf.get_distribution_tenant(Identifier=tenant_id),
            lambda r: r["DistributionTenant"]["Status"] == "Deployed",
            timeout_s=600,
            interval_s=15,
        )["ETag"]
    cf.delete_distribution_tenant(Id=tenant_id, IfMatch=etag)


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "delete-tenant-in-use check",
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
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
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


def _create_connection_group(ctx) -> dict:
    # CreateDistributionTenant rejects a tenant bound to a DISABLED connection group with
    # InvalidAssociation ("The specified connection group is disabled"), so the group this
    # check attaches the tenant to must itself be enabled.
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    resp = cf.create_connection_group(
        Name=name, Enabled=True,
        Tags={"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
    )
    cg = resp["ConnectionGroup"]
    cg_id = cg["Id"]
    ctx.on_cleanup(lambda: _delete_connection_group(cf, cg_id))
    return cg


def _start_disabling(ctx, dist_id: str, cg_id: str) -> None:
    """Teardown: issue Enabled=False for the connection group and the distribution without
    waiting; their own teardowns then only wait for Deployed."""
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")
    try:
        got = cf.get_connection_group(Identifier=cg_id)
        if got["ConnectionGroup"].get("Enabled"):
            cf.update_connection_group(Id=cg_id, IfMatch=got["ETag"], Enabled=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        config = cfg_resp["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            cf.update_distribution(Id=dist_id, DistributionConfig=config, IfMatch=cfg_resp["ETag"])
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


def _delete_connection_group(cf, cg_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        got = cf.get_connection_group(Identifier=cg_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFound":
            return
        raise
    etag = got["ETag"]
    if got["ConnectionGroup"].get("Enabled"):
        etag = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)["ETag"]
    etag = _poll_until(
        lambda: cf.get_connection_group(Identifier=cg_id),
        lambda r: r["ConnectionGroup"]["Status"] == "Deployed",
        timeout_s=600,
        interval_s=15,
    )["ETag"]
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
