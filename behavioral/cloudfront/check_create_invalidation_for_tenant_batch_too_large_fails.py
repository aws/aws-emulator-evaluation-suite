"""create-invalidation-for-tenant-batch-too-large-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-invalidation-for-tenant-batch-too-large-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

# CloudFront invalidation batches accept at most 3,000 explicit (non-wildcard) paths in
# progress at once; see "Specifying the objects to invalidate" in the CloudFront Developer
# Guide. A single request with 3,001 consistent (Quantity == len(Items)) paths pushes the
# in-flight path count over that cap and is rejected with TooManyInvalidationsInProgress;
# BatchTooLarge is a different, request-body-size limit.
_TOO_MANY_PATHS = 3001


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A tenant invalidation batch over the 3,000 in-progress path cap is rejected with
    TooManyInvalidationsInProgress and records nothing beyond the small positive-control batch."""
    cf = ctx.client("cloudfront")

    dist_id = _create_multi_tenant_distribution(ctx)
    cg = _create_connection_group(ctx)
    domain = _domain_name(ctx, "tenant")
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenant-"),
        Domains=[{"Domain": domain}],
        ConnectionGroupId=cg["Id"],
        Enabled=False,
        # Every distribution tenant needs at least one certificate; we don't own `domain`, so
        # the managed certificate sits in pending validation forever, but the CreateDistribution-
        # Tenant call under test succeeds either way.
        ManagedCertificateRequest={"ValidationTokenHost": "self-hosted", "PrimaryDomainName": domain},
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    tenant_id = tenant_resp["DistributionTenant"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_distribution_tenant(
        Id=tenant_id, IfMatch=cf.get_distribution_tenant(Identifier=tenant_id)["ETag"]
    ))

    before = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    before_count = before["InvalidationList"]["Quantity"]

    # Positive control: a small, consistent path batch succeeds -- proves the tenant and
    # credentials are otherwise healthy before the negative is attempted.
    small_batch = {
        "Paths": {"Quantity": 2, "Items": ["/sim2real-ok/one", "/sim2real-ok/two"]},
        "CallerReference": ctx.unique_name("sim2real-invalidation-ok-"),
    }
    ok_resp = cf.create_invalidation_for_distribution_tenant(Id=tenant_id, InvalidationBatch=small_batch)
    assert ok_resp["Invalidation"]["Status"] in ("InProgress", "Completed"), (
        f"expected the positive-control invalidation to be accepted, got status "
        f"{ok_resp['Invalidation']['Status']!r}"
    )

    after_ok = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    after_ok_count = after_ok["InvalidationList"]["Quantity"]
    assert after_ok_count == before_count + 1, (
        f"expected exactly one new invalidation after the positive control, "
        f"before={before_count} after={after_ok_count}"
    )

    # Negative: a consistent but oversized path batch.
    too_many_paths = [f"/sim2real-batch-too-large/{i}" for i in range(_TOO_MANY_PATHS)]
    huge_batch = {
        "Paths": {"Quantity": len(too_many_paths), "Items": too_many_paths},
        "CallerReference": ctx.unique_name("sim2real-invalidation-huge-"),
    }
    code, msg = _error(lambda: cf.create_invalidation_for_distribution_tenant(
        Id=tenant_id, InvalidationBatch=huge_batch
    ))
    assert code == "TooManyInvalidationsInProgress", (
        f"expected TooManyInvalidationsInProgress, got {code!r}"
    )
    too_many_msg = (
        "Processing your request will cause you to exceed the maximum number of in-progress "
        "invalidations."
    )
    assert msg == too_many_msg, f"expected message {too_many_msg!r}, got {msg!r}"

    # Effect absent: no new invalidation was recorded for the tenant beyond the positive control.
    after_rejected = cf.list_invalidations_for_distribution_tenant(Id=tenant_id)
    assert after_rejected["InvalidationList"]["Quantity"] == after_ok_count, (
        f"expected no new invalidation after the rejected batch, "
        f"before={after_ok_count} after={after_rejected['InvalidationList']['Quantity']}"
    )


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _domain_name(ctx, label: str) -> str:
    # CloudFront rejects any *.example.com/.example.org/.example.net domain outright with
    # InvalidArgument ("Domain Name not allowed") -- those roots are IANA-reserved documentation
    # domains and CloudFront denylists them explicitly. A random, unregistered .com name passes
    # the same format/denylist check without requiring us to actually own or DNS-validate it
    # (CloudFront only validates ownership later, via the pending managed-certificate TXT record).
    raw = ctx.unique_name(f"sim2real-{label}-").lower()
    cleaned = "".join(ch if (ch.isalnum() or ch == "-") else "-" for ch in raw).strip("-")
    return f"{cleaned}.com"


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "invalidation batch-too-large check",
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
    # CreateDistribution has no inline Tags param (unlike CreateDistributionTenant /
    # CreateConnectionGroup) -- tag explicitly so a leaked distribution is findable by a
    # Resource Groups Tagging API search.
    cf.tag_resource(
        Resource=resp["Distribution"]["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
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


def _create_connection_group(ctx) -> dict:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    # CreateDistributionTenant rejects association with a disabled connection group
    # (InvalidAssociation: "The specified connection group is disabled"), so the group must be
    # created Enabled=True; DeleteConnectionGroup then requires it disabled first (mirrors the
    # distribution disable-before-delete rule), so cleanup disables before deleting.
    resp = cf.create_connection_group(
        Name=name,
        Enabled=True,
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    cg = resp["ConnectionGroup"]
    cg_id = cg["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_connection_group(cf, cg_id))
    return cg


def _disable_and_delete_connection_group(cf, cg_id: str) -> None:
    got = cf.get_connection_group(Identifier=cg_id)
    etag = got["ETag"]
    if got["ConnectionGroup"].get("Enabled"):
        etag = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)["ETag"]
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
