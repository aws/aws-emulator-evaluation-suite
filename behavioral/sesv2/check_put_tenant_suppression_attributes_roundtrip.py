"""put-tenant-suppression-attributes-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-tenant-suppression-attributes-roundtrip"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTenantSuppressionAttributes durably updates tenant-scoped suppression settings, and a
    subsequent GetTenant reflects the latest values (overwriting the prior ones)."""
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")

    sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, tenant_name))

    sesv2.put_tenant_suppression_attributes(
        TenantName=tenant_name,
        SuppressionScope="TENANT",
        SuppressedReasons=["BOUNCE", "COMPLAINT"],
    )
    first = sesv2.get_tenant(TenantName=tenant_name)["Tenant"]["SuppressionAttributes"]
    assert first["SuppressionScope"] == "TENANT", (
        f"expected SuppressionScope TENANT after first PutTenantSuppressionAttributes, got {first['SuppressionScope']!r}"
    )
    assert sorted(first["SuppressedReasons"]) == ["BOUNCE", "COMPLAINT"], (
        f"expected SuppressedReasons [BOUNCE, COMPLAINT], got {sorted(first['SuppressedReasons'])}"
    )

    # Overwrite with a different configuration; GetTenant must reflect the LATEST call, not
    # the first one, proving the update is durable rather than write-once.
    sesv2.put_tenant_suppression_attributes(
        TenantName=tenant_name,
        SuppressionScope="ACCOUNT",
        SuppressedReasons=["COMPLAINT"],
    )
    second = sesv2.get_tenant(TenantName=tenant_name)["Tenant"]["SuppressionAttributes"]
    assert second["SuppressionScope"] == "ACCOUNT", (
        f"expected SuppressionScope ACCOUNT after second PutTenantSuppressionAttributes (overwrite), got {second['SuppressionScope']!r}"
    )
    assert sorted(second["SuppressedReasons"]) == ["COMPLAINT"], (
        f"expected SuppressedReasons [COMPLAINT] after overwrite, got {sorted(second['SuppressedReasons'])}"
    )


def _safe_delete_tenant(sesv2, name: str) -> None:
    try:
        sesv2.delete_tenant(TenantName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
