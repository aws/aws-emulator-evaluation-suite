"""tenant-resource-association-duplicate-rejected."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-resource-association-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Associating the same resource to the same tenant twice raises AlreadyExistsException,
    does not duplicate the association, and the tenant can still be associated with a
    different resource afterward."""
    sesv2 = ctx.client("sesv2")
    tenant_name = ctx.unique_name("sim2real-tenant-")
    cfg_set_name = ctx.unique_name("sim2real-cfgset-")
    other_cfg_set_name = ctx.unique_name("sim2real-cfgset-ctl-")

    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    sesv2.create_tenant(TenantName=tenant_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, tenant_name))

    sesv2.create_configuration_set(ConfigurationSetName=cfg_set_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: _safe_delete_configuration_set(sesv2, cfg_set_name))
    resource_arn = _configuration_set_arn(ctx, cfg_set_name)

    sesv2.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=resource_arn)
    ctx.on_cleanup(lambda: _safe_delete_association(sesv2, tenant_name, resource_arn))

    code, msg = _error(
        lambda: sesv2.create_tenant_resource_association(
            TenantName=tenant_name, ResourceArn=resource_arn
        )
    )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    expected_msg = f"Resources {resource_arn} has already been associated with tenant {tenant_name}"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the association was not duplicated - exactly one entry for this resource.
    resources = sesv2.list_tenant_resources(TenantName=tenant_name)["TenantResources"]
    matching = [r for r in resources if r["ResourceArn"] == resource_arn]
    assert len(matching) == 1, f"expected exactly 1 association for {resource_arn}, found {len(matching)}"

    # Positive control: associating a distinct resource to the same tenant still works.
    sesv2.create_configuration_set(ConfigurationSetName=other_cfg_set_name, Tags=resource_tags)
    ctx.on_cleanup(lambda: _safe_delete_configuration_set(sesv2, other_cfg_set_name))
    other_resource_arn = _configuration_set_arn(ctx, other_cfg_set_name)

    sesv2.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=other_resource_arn)
    ctx.on_cleanup(lambda: _safe_delete_association(sesv2, tenant_name, other_resource_arn))

    resources_after = sesv2.list_tenant_resources(TenantName=tenant_name)["TenantResources"]
    assert any(r["ResourceArn"] == other_resource_arn for r in resources_after), (
        f"expected {other_resource_arn} in tenant resources after positive-control association, "
        f"got {[r['ResourceArn'] for r in resources_after]}"
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
