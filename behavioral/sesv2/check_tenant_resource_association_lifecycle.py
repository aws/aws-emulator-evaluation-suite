"""tenant-resource-association-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-resource-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating a resource to a tenant makes it visible via both ListTenantResources and
    ListResourceTenants; disassociation removes it from both views."""
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")
    cfg_set_name = ctx.unique_name("sim2real-cfgset-")

    sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, tenant_name))

    sesv2.create_configuration_set(
        ConfigurationSetName=cfg_set_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe_delete_configuration_set(sesv2, cfg_set_name))

    resource_arn = _configuration_set_arn(ctx, cfg_set_name)

    sesv2.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=resource_arn)

    tenant_resources = _list_tenant_resource_arns(sesv2, tenant_name)
    assert resource_arn in tenant_resources, "associated resource missing from ListTenantResources"

    resource_tenants = _list_resource_tenant_names(sesv2, resource_arn)
    assert tenant_name in resource_tenants, "associated tenant missing from ListResourceTenants"

    sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=resource_arn)

    tenant_resources_after = _list_tenant_resource_arns(sesv2, tenant_name)
    assert resource_arn not in tenant_resources_after, (
        f"disassociated resource {resource_arn} still visible in ListTenantResources: "
        f"{tenant_resources_after}"
    )

    resource_tenants_after = _list_resource_tenant_names(sesv2, resource_arn)
    assert tenant_name not in resource_tenants_after, (
        f"disassociated tenant {tenant_name} still visible in ListResourceTenants: "
        f"{resource_tenants_after}"
    )


def _configuration_set_arn(ctx, cfg_set_name: str) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:ses:{ctx.region}:{account_id}:configuration-set/{cfg_set_name}"


def _list_tenant_resource_arns(sesv2, tenant_name: str) -> set[str]:
    arns: set[str] = set()
    token = None
    while True:
        kwargs = {"TenantName": tenant_name}
        if token:
            kwargs["NextToken"] = token
        resp = sesv2.list_tenant_resources(**kwargs)
        for res in resp.get("TenantResources", []):
            arns.add(res["ResourceArn"])
        token = resp.get("NextToken")
        if not token:
            break
    return arns


def _list_resource_tenant_names(sesv2, resource_arn: str) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"ResourceArn": resource_arn}
        if token:
            kwargs["NextToken"] = token
        resp = sesv2.list_resource_tenants(**kwargs)
        for entry in resp.get("ResourceTenants", []):
            names.add(entry["TenantName"])
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


def _safe_delete_configuration_set(sesv2, name: str) -> None:
    try:
        sesv2.delete_configuration_set(ConfigurationSetName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
