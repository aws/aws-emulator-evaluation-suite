"""tenant-name-validation-and-associated-resource-delete-blocked."""
from __future__ import annotations

from typing import Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tenant-name-validation-and-associated-resource-delete-blocked"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTenant and GetTenant both refuse a name outside [A-Za-z0-9_-] with the identical
    BadRequestException. Deleting a configuration set still associated with a tenant is refused
    and the set survives a read; removing the association lets the delete succeed.
    """
    sesv2 = ctx.client("sesv2")

    bad_name = "bad name!"
    invalid_name = ("BadRequestException",
                     f"Invalid tenant name <{bad_name}>: only alphanumeric ASCII characters, "
                     "'_', and '-' are allowed.")
    code, msg = _expect_error(lambda: sesv2.create_tenant(TenantName=bad_name))
    assert (code, msg) == invalid_name, f"expected {invalid_name!r}, got {(code, msg)!r}"

    # The name refusal through the API: GetTenant validates the name shape before any lookup,
    # so the same name is refused with the identical BadRequestException, not NotFoundException.
    get_code, get_msg = _expect_error(lambda: sesv2.get_tenant(TenantName=bad_name))
    assert (get_code, get_msg) == invalid_name, f"expected {invalid_name!r}, got {(get_code, get_msg)!r}"

    # Positive control for the name rule: a name built only from the allowed characters creates.
    tenant_name = ctx.unique_name("sim2real-tenant-")
    sesv2.create_tenant(TenantName=tenant_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, tenant_name))
    created = sesv2.get_tenant(TenantName=tenant_name)["Tenant"]
    assert created["TenantName"] == tenant_name, (
        f"expected GetTenant to reflect {tenant_name!r}, got {created['TenantName']!r}"
    )

    cfg_set_name = ctx.unique_name("sim2real-cfgset-")
    cfg_set_arn = f"arn:aws:ses:{ctx.region}:{ctx.account}:configuration-set/{cfg_set_name}"
    sesv2.create_configuration_set(
        ConfigurationSetName=cfg_set_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(
        lambda: _safe_delete_configuration_set(sesv2, cfg_set_name, cfg_set_arn, tenant_name)
    )

    sesv2.create_tenant_resource_association(TenantName=tenant_name, ResourceArn=cfg_set_arn)

    delete_blocked = (
        "BadRequestException",
        f"Cannot delete <{cfg_set_arn}> because it has tenant associations. Remove all tenant "
        "associations and try again.",
    )
    block_code, block_msg = _expect_error(
        lambda: sesv2.delete_configuration_set(ConfigurationSetName=cfg_set_name)
    )
    assert (block_code, block_msg) == delete_blocked, (
        f"expected {delete_blocked!r}, got {(block_code, block_msg)!r}"
    )

    # Survival read: the blocked delete did not remove the configuration set.
    survived = sesv2.get_configuration_set(ConfigurationSetName=cfg_set_name)
    assert survived["ConfigurationSetName"] == cfg_set_name, (
        f"expected the blocked delete to leave {cfg_set_name!r} in place, "
        f"GetConfigurationSet returned {survived['ConfigurationSetName']!r}"
    )

    sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=cfg_set_arn)

    resources = _list_tenant_resource_arns(sesv2, tenant_name)
    assert resources == set(), (
        f"expected ListTenantResources({tenant_name!r}) empty after disassociation, got {resources!r}"
    )

    # Positive control for the delete rule: the same delete now succeeds once unblocked.
    sesv2.delete_configuration_set(ConfigurationSetName=cfg_set_name)

    deleted = ("NotFoundException", f"Configuration set <{cfg_set_name}> does not exist.")
    final_code, final_msg = _expect_error(
        lambda: sesv2.get_configuration_set(ConfigurationSetName=cfg_set_name)
    )
    assert (final_code, final_msg) == deleted, f"expected {deleted!r}, got {(final_code, final_msg)!r}"


def _expect_error(fn: Callable[[], object]) -> tuple[str, str]:
    """The (Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _list_tenant_resource_arns(sesv2, tenant_name: str) -> set:
    arns: set = set()
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


def _safe_delete_tenant(sesv2, name: str) -> None:
    try:
        sesv2.delete_tenant(TenantName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_configuration_set(sesv2, name: str, arn: str, tenant_name: str) -> None:
    """Backstop teardown: drop a dangling association first if the main flow left one."""
    try:
        sesv2.delete_configuration_set(ConfigurationSetName=name)
        return
    except ClientError as err:
        error = err.response["Error"]
        if error["Code"] == "NotFoundException":
            return
        in_use = error["Code"] == "BadRequestException" and error.get("Message", "") == (
            f"Cannot delete <{arn}> because it has tenant associations. Remove all tenant "
            "associations and try again."
        )
        if not in_use:
            raise
    try:
        sesv2.delete_tenant_resource_association(TenantName=tenant_name, ResourceArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise
    sesv2.delete_configuration_set(ConfigurationSetName=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
