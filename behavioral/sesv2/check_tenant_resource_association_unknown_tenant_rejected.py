"""tenant-resource-association-unknown-tenant-rejected."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-resource-association-unknown-tenant-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTenantResourceAssociation against a non-existent tenant name raises
    NotFoundException, leaves the resource unassociated with anyone, and a real tenant can
    still be associated with the same resource afterward."""
    sesv2 = ctx.client("sesv2")
    unknown_tenant_name = ctx.unique_name("sim2real-tenant-unknown-")
    real_tenant_name = ctx.unique_name("sim2real-tenant-real-")
    cfg_set_name = ctx.unique_name("sim2real-cfgset-")

    sesv2.create_configuration_set(ConfigurationSetName=cfg_set_name)
    ctx.on_cleanup(lambda: _safe_delete_configuration_set(sesv2, cfg_set_name))
    resource_arn = _configuration_set_arn(ctx, cfg_set_name)

    code, msg = _error(
        lambda: sesv2.create_tenant_resource_association(
            TenantName=unknown_tenant_name, ResourceArn=resource_arn
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_msg = f"The requested tenant <{unknown_tenant_name}> does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the resource has no tenant associations at all yet.
    resource_tenants = sesv2.list_resource_tenants(ResourceArn=resource_arn)["ResourceTenants"]
    assert resource_tenants == [], f"expected no associations, got {resource_tenants!r}"

    # Positive control: associating the same resource to a real tenant succeeds.
    sesv2.create_tenant(TenantName=real_tenant_name)
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, real_tenant_name))
    sesv2.create_tenant_resource_association(TenantName=real_tenant_name, ResourceArn=resource_arn)
    ctx.on_cleanup(
        lambda: _safe_delete_association(sesv2, real_tenant_name, resource_arn)
    )

    resource_tenants_after = sesv2.list_resource_tenants(ResourceArn=resource_arn)["ResourceTenants"]
    assert any(t["TenantName"] == real_tenant_name for t in resource_tenants_after), (
        f"expected {real_tenant_name!r} among associated tenants, got {resource_tenants_after!r}"
    )


def _configuration_set_arn(ctx, cfg_set_name: str) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:ses:{ctx.region}:{account_id}:configuration-set/{cfg_set_name}"


def _error(fn: Callable[[], object]) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message) it is refused with. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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


def _safe_delete_association(sesv2, tenant_name: str, resource_arn: str) -> None:
    try:
        sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=resource_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
