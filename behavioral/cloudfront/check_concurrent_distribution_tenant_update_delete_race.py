"""concurrent-distribution-tenant-update-delete-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-distribution-tenant-update-delete-race"
GROUP = "concurrency"
SERVICES = ["cloudfront"]

# Every UpdateDistributionTenant that touches Domains has to carry a certificate path too,
# and it must not pin PrimaryDomainName (see the create call below for why).
_MANAGED_CERT_REQUEST = {"ValidationTokenHost": "self-hosted"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DeleteDistributionTenant with a superseded IfMatch raced against an UpdateDistributionTenant
    with the current one: the update wins, the delete fails with PreconditionFailed, and the tenant
    still exists carrying the update's domain."""
    cf = ctx.client("cloudfront")

    dist_id = _create_multi_tenant_distribution(ctx)
    cg = _create_connection_group(ctx)

    domain_v1 = f"{ctx.unique_name('sim2real-tenrace-v1').lower()}.sim2real.test"
    tenant_resp = cf.create_distribution_tenant(
        DistributionId=dist_id,
        Name=ctx.unique_name("sim2real-tenrace-"),
        Domains=[{"Domain": domain_v1}],
        ConnectionGroupId=cg["Id"],
        Enabled=False,
        # Every distribution tenant needs at least one certificate; we don't own
        # `domain_v1`, so ValidationTokenHost="self-hosted" defers domain-ownership
        # verification to whoever hosts the token and the certificate is left pending
        # validation, while CreateDistributionTenant -- the call this check needs to
        # succeed so it can race against it -- succeeds. "cloudfront" instead demands
        # synchronously that the domain already resolve to a CloudFront resource, which
        # a domain nobody owns never will, so it fails with InvalidArgument.
        # PrimaryDomainName is deliberately OMITTED: pinning it to `domain_v1` makes every
        # later UpdateDistributionTenant that swaps the domain list fail with InvalidArgument
        # ("The specified Primary Domain Name is not valid ... not part of the Domain Names of
        # the Distribution Tenant"), which is the version-advancing step this race needs.
        ManagedCertificateRequest=_MANAGED_CERT_REQUEST,
    )
    tenant_id = tenant_resp["DistributionTenant"]["Id"]
    stale_etag = tenant_resp["ETag"]  # captured at v1 -- will be superseded below

    def _final_cleanup():
        try:
            latest = cf.get_distribution_tenant(Identifier=tenant_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFound":
                raise
            return
        cf.delete_distribution_tenant(Id=tenant_id, IfMatch=latest["ETag"])

    ctx.on_cleanup(_final_cleanup)

    # Legitimate sequential update: v1 -> v2. `stale_etag` (v1) is now out of date.
    domain_v2 = f"{ctx.unique_name('sim2real-tenrace-v2').lower()}.sim2real.test"
    advance_resp = cf.update_distribution_tenant(
        Id=tenant_id,
        Domains=[{"Domain": domain_v2}],
        IfMatch=stale_etag,
        ManagedCertificateRequest=_MANAGED_CERT_REQUEST,
    )
    current_etag = advance_resp["ETag"]
    v2_domains = {d["Domain"] for d in advance_resp["DistributionTenant"]["Domains"]}
    assert v2_domains == {domain_v2}, f"expected the v1->v2 update to land, got domains {v2_domains!r}"

    domain_v3 = f"{ctx.unique_name('sim2real-tenrace-v3').lower()}.sim2real.test"

    def _do_update():
        try:
            resp = cf.update_distribution_tenant(
                Id=tenant_id,
                Domains=[{"Domain": domain_v3}],
                IfMatch=current_etag,
                ManagedCertificateRequest=_MANAGED_CERT_REQUEST,
            )
            return ("ok", resp)
        except Exception as exc:  # noqa: BLE001
            return ("error", _error_code_of(exc))

    def _do_delete():
        try:
            cf.delete_distribution_tenant(Id=tenant_id, IfMatch=stale_etag)
            return ("ok", None)
        except Exception as exc:  # noqa: BLE001
            return ("error", _error_code_of(exc))

    with ThreadPoolExecutor(max_workers=2) as pool:
        update_future = pool.submit(_do_update)
        delete_future = pool.submit(_do_delete)
        update_result = update_future.result()
        delete_result = delete_future.result()

    assert update_result[0] == "ok", f"expected the current-version update to succeed, got {update_result!r}"
    won_domain = update_result[1]["DistributionTenant"]["Domains"][0]["Domain"]
    assert won_domain == domain_v3, f"expected the winning update's response to carry {domain_v3!r}, got {won_domain!r}"

    assert delete_result[0] == "error", f"expected the stale-version delete to be rejected, got {delete_result!r}"
    assert delete_result[1] == "PreconditionFailed", (
        f"expected PreconditionFailed for the stale-version delete, got {delete_result[1]!r}"
    )

    # No corrupted partial state: the tenant still exists and reflects the winning update.
    final = cf.get_distribution_tenant(Identifier=tenant_id)
    final_id = final["DistributionTenant"]["Id"]
    assert final_id == tenant_id, f"expected tenant {tenant_id!r} to still exist, independent read returned {final_id!r}"
    final_domains = {d["Domain"] for d in final["DistributionTenant"]["Domains"]}
    assert final_domains == {domain_v3}, (
        f"expected the independent read to reflect the winning update's domain {domain_v3!r}, got {final_domains!r}"
    )


def _error_code_of(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return None


def _create_multi_tenant_distribution(ctx) -> str:
    cf = ctx.client("cloudfront")
    caller_ref = ctx.unique_name("sim2real-mt-")
    config = {
        "CallerReference": caller_ref,
        "Comment": "tenant update-delete race check",
        "Enabled": True,
        "ConnectionMode": "tenant-only",
        "TenantConfig": {"ParameterDefinitions": []},
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": "origin.sim2real.test",
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


def _create_connection_group(ctx) -> dict:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    # A DistributionTenant can only attach to an ENABLED connection group
    # (CreateDistributionTenant otherwise rejects with InvalidAssociation:
    # "The specified connection group is disabled"), so cleanup must disable
    # it before DeleteConnectionGroup, which itself rejects an enabled group
    # with ResourceNotDisabled.
    resp = cf.create_connection_group(Name=name, Enabled=True)
    cg = resp["ConnectionGroup"]
    cg_id = cg["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_connection_group(cf, cg_id))
    return cg


def _disable_and_delete_connection_group(cf, cg_id: str) -> None:
    got = cf.get_connection_group(Identifier=cg_id)
    etag = got["ETag"]
    if got["ConnectionGroup"]["Enabled"]:
        etag = cf.update_connection_group(Id=cg_id, IfMatch=etag, Enabled=False)["ETag"]
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
