"""tenant-resource-association-delete-unknown-rejected."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-resource-association-delete-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTenantResourceAssociation for a resource that was never associated to the tenant
    raises NotFoundException, leaves the tenant's real (unrelated) association untouched, and
    that real association can still be deleted afterward."""
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")
    associated_cfg_set_name = ctx.unique_name("sim2real-cfgset-assoc-")
    unassociated_cfg_set_name = ctx.unique_name("sim2real-cfgset-none-")

    sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, tenant_name))

    sesv2.create_configuration_set(
        ConfigurationSetName=associated_cfg_set_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe_delete_configuration_set(sesv2, associated_cfg_set_name))
    associated_arn = _configuration_set_arn(ctx, associated_cfg_set_name)

    # NOTE: deliberately do NOT create this configuration set. Real AWS treats
    # DeleteTenantResourceAssociation as an idempotent no-op (HTTP 200, no error)
    # when the ResourceArn refers to a resource that IS associated (or, empirically,
    # even a valid-but-unassociated *existing* resource) — the NotFoundException is
    # tied to the underlying resource not existing at all, not to the association
    # itself being absent. So use an ARN for a configuration set that was never
    # created to reach the real "resource doesn't exist" precondition.
    unassociated_arn = _configuration_set_arn(ctx, unassociated_cfg_set_name)

    # Only the first resource is actually associated with the tenant.
    sesv2.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=associated_arn)
    ctx.on_cleanup(lambda: _safe_delete_association(sesv2, tenant_name, associated_arn))

    code, msg = _error(
        lambda: sesv2.delete_tenant_resource_association(
            TenantName=tenant_name, ResourceArn=unassociated_arn
        )
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_msg = f"Configuration set <{unassociated_cfg_set_name}> does not exist:"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the real association was not touched by the erroneous delete.
    resources = sesv2.list_tenant_resources(TenantName=tenant_name)["TenantResources"]
    assert any(r["ResourceArn"] == associated_arn for r in resources), (
        f"expected {associated_arn} still associated, resources were {resources!r}"
    )

    # Positive control: deleting the real association succeeds.
    sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=associated_arn)
    resources_after = sesv2.list_tenant_resources(TenantName=tenant_name)["TenantResources"]
    assert not any(r["ResourceArn"] == associated_arn for r in resources_after), (
        f"expected {associated_arn} gone, resources were {resources_after!r}"
    )

    # A second delete of the now-gone association is idempotent (HTTP 200, no error):
    # real AWS's NotFoundException is tied to the underlying resource not existing at
    # all (see the comment above `unassociated_arn`), not to the association being
    # absent. A refusal here raises ClientError and fails the check.
    sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=associated_arn)


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
