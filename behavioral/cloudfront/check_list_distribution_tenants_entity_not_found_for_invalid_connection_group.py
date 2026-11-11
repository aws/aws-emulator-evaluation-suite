"""list-distribution-tenants-entity-not-found-for-invalid-connection-group."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-distribution-tenants-entity-not-found-for-invalid-connection-group"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionTenants does not validate AssociationFilter.ConnectionGroupId existence.

    A nonexistent connection group id returns 200 with an empty page, not EntityNotFound.
    """
    cf = ctx.client("cloudfront")
    cg_id = _create_connection_group(ctx)

    fake_cg_id = ctx.unique_name("nonexistent-cg-")
    fake_resp = cf.list_distribution_tenants(AssociationFilter={"ConnectionGroupId": fake_cg_id})
    assert fake_resp["DistributionTenantList"] == [], (
        f"expected an empty page for a connection group id that never existed, "
        f"got {fake_resp['DistributionTenantList']!r}"
    )

    # Same shape for a real, tenant-less connection group: proves the empty result above is
    # ordinary filtering, not a coincidence of a malformed or rejected request.
    real_resp = cf.list_distribution_tenants(AssociationFilter={"ConnectionGroupId": cg_id})
    assert real_resp["DistributionTenantList"] == [], (
        f"expected an empty page for a real connection group with no tenants, "
        f"got {real_resp['DistributionTenantList']!r}"
    )


def _create_connection_group(ctx) -> str:
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-cg-")
    resp = cf.create_connection_group(
        Name=name,
        Enabled=True,
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    cg_id = resp["ConnectionGroup"]["Id"]
    ctx.on_cleanup(lambda: _disable_and_delete_connection_group(ctx, cg_id))
    return cg_id


def _disable_and_delete_connection_group(ctx, cg_id: str) -> None:
    # Delete needs only the current ETag and Enabled=False, not Status "Deployed"; deployment
    # can take many minutes, so teardown must not wait for it.
    cf = ctx.client("cloudfront")
    try:
        got = cf.get_connection_group(Identifier=cg_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFound":
            raise
        return
    etag = got["ETag"]
    if got["ConnectionGroup"].get("Enabled"):
        disable_resp = cf.update_connection_group(Id=cg_id, Enabled=False, IfMatch=etag)
        etag = disable_resp["ETag"]
    cf.delete_connection_group(Id=cg_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
