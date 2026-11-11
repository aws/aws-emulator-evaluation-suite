"""tenant-create-get-list-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-create-get-list-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created tenant is retrievable via GetTenant and appears in ListTenants; DeleteTenant
    fully removes it from ListTenants."""
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-tenant-")

    sesv2.create_tenant(TenantName=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, name))

    got = sesv2.get_tenant(TenantName=name)["Tenant"]
    assert got["TenantName"] == name, f"expected TenantName {name!r}, got {got.get('TenantName')!r}"
    assert got["TenantId"], "GetTenant returned an empty TenantId"
    assert got["TenantArn"], "GetTenant returned an empty TenantArn"

    names_before = _list_all_tenant_names(sesv2)
    assert name in names_before, "newly created tenant did not appear in ListTenants"

    sesv2.delete_tenant(TenantName=name)

    names_after = _list_all_tenant_names(sesv2)
    assert name not in names_after, "deleted tenant is still visible in ListTenants"


def _list_all_tenant_names(sesv2) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = sesv2.list_tenants(**kwargs)
        for tenant in resp.get("Tenants", []):
            names.add(tenant["TenantName"])
        token = resp.get("NextToken")
        if not token:
            break
    return names


def _safe_delete_tenant(sesv2, name: str) -> None:
    try:
        sesv2.delete_tenant(TenantName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
