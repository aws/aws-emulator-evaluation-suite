"""a-resource-belongs-to-at-most-one-tenant-and-both-views-agree."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "a-resource-belongs-to-at-most-one-tenant-and-both-views-agree"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A resource may be associated with two SES tenants at once, both views agree after each change,
    and DeleteTenant on a tenant still holding an association succeeds and its GetTenant and
    ListTenantResources then fail with NotFoundException and the exact message.

    Reference: https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_CreateTenantResourceAssociation.html
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    sesv2 = ctx.client("sesv2")
    account = ctx.client("sts").get_caller_identity()["Account"]

    first_tenant = _create_tenant(ctx, "t1-")
    second_tenant = _create_tenant(ctx, "t2-")
    resource = _configuration_set_arn(
        ctx, _create_configuration_set(ctx, "shared-", account, teardown_deadline), account
    )
    control = _configuration_set_arn(
        ctx, _create_configuration_set(ctx, "control-", account, teardown_deadline), account
    )

    # Positive control, and the baseline for the inverse invariant: the resource belongs to the first
    # tenant and to nothing else, and a second resource on the second tenant proves both tenants are
    # usable.
    sesv2.create_tenant_resource_association(TenantName=first_tenant, ResourceArn=resource)
    ctx.on_cleanup(lambda: _safe_delete_association(sesv2, first_tenant, resource))
    sesv2.create_tenant_resource_association(TenantName=second_tenant, ResourceArn=control)
    ctx.on_cleanup(lambda: _safe_delete_association(sesv2, second_tenant, control))

    _assert_views_are_inverses(sesv2, {first_tenant: {resource}, second_tenant: {control}}, "baseline")

    # SES does not enforce at-most-one-tenant. Claiming an already-associated resource for
    # a second tenant succeeds outright (no AlreadyExistsException), and the resource shows up
    # under BOTH tenants in both views.
    try:
        sesv2.create_tenant_resource_association(TenantName=second_tenant, ResourceArn=resource)
    except ClientError as err:
        raise AssertionError(
            f"associating {resource} with a SECOND tenant {second_tenant} while it is already "
            f"associated with {first_tenant} was refused with {err.response['Error']['Code']!r}; "
            f"SES is expected to accept shared membership"
        ) from err
    ctx.on_cleanup(lambda: _safe_delete_association(sesv2, second_tenant, resource))
    _assert_views_are_inverses(
        sesv2,
        {first_tenant: {resource}, second_tenant: {control, resource}},
        "after a second tenant claimed the resource and SES accepted it",
    )

    # Removing it from one tenant must not remove it from the other.
    sesv2.delete_tenant_resource_association(TenantName=second_tenant, ResourceArn=resource)
    _assert_views_are_inverses(
        sesv2,
        {first_tenant: {resource}, second_tenant: {control}},
        "after disassociating the resource from only the second tenant",
    )

    # DeleteTenant on a tenant that still holds an association succeeds unconditionally (it is never
    # refused), and the tenant-keyed views are torn down with the tenant: GetTenant and
    # ListTenantResources both answer NotFoundException.
    holdings = _tenant_resources(sesv2, second_tenant)
    assert holdings, (
        f"precondition for the delete leg: tenant {second_tenant} should still hold at least one "
        f"association, ListTenantResources reports none"
    )
    try:
        sesv2.delete_tenant(TenantName=second_tenant)
    except ClientError as err:
        raise AssertionError(
            f"DeleteTenant({second_tenant}) was refused with {err.response['Error']['Code']!r} "
            f"while it still held {sorted(holdings)}; expected it to succeed unconditionally"
        ) from err

    gone = ("NotFoundException", f"The requested tenant <{second_tenant}> does not exist.")
    get_error = _call_error(lambda: sesv2.get_tenant(TenantName=second_tenant))
    assert get_error == gone, (
        f"GetTenant({second_tenant}) after DeleteTenant returned {get_error!r}, expected "
        f"NotFoundException"
    )
    list_error = _call_error(lambda: sesv2.list_tenant_resources(TenantName=second_tenant))
    assert list_error == gone, (
        f"ListTenantResources({second_tenant}) after DeleteTenant returned {list_error!r}, "
        f"expected NotFoundException — the tenant-keyed index should be torn down with the tenant"
    )


def _create_tenant(ctx, prefix: str) -> str:
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-" + prefix)
    sesv2.create_tenant(
        TenantName=name,
        Tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: _safe_delete_tenant(sesv2, name))
    return name


def _create_configuration_set(ctx, prefix: str, account: str, teardown_deadline) -> str:
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-behav-" + prefix)
    sesv2.create_configuration_set(
        ConfigurationSetName=name,
        Tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(
        lambda: _safe_delete_configuration_set(
            sesv2, name, _configuration_set_arn(ctx, name, account), teardown_deadline
        )
    )
    return name


def _configuration_set_arn(ctx, name: str, account: str) -> str:
    # The `aws` partition literal: outside it the ARN would have to come from a returned ARN.
    return f"arn:aws:ses:{ctx.region}:{account}:configuration-set/{name}"


def _tenant_resources(sesv2, tenant: str) -> set[str]:
    arns: set[str] = set()
    token = None
    while True:
        kwargs = {"TenantName": tenant}
        if token:
            kwargs["NextToken"] = token
        page = sesv2.list_tenant_resources(**kwargs)
        for entry in page.get("TenantResources", []):
            arns.add(entry["ResourceArn"])
        token = page.get("NextToken")
        if not token:
            break
    return arns


def _resource_tenants(sesv2, resource_arn: str) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"ResourceArn": resource_arn}
        if token:
            kwargs["NextToken"] = token
        page = sesv2.list_resource_tenants(**kwargs)
        for entry in page.get("ResourceTenants", []):
            names.add(entry["TenantName"])
        token = page.get("NextToken")
        if not token:
            break
    return names


def _assert_views_are_inverses(sesv2, expected: dict, phase: str) -> None:
    """`expected` maps tenant -> the exact resource set it should hold. Both directions are checked:
    ListTenantResources must equal that set, and for every resource mentioned anywhere,
    ListResourceTenants must name exactly the tenants that hold it."""
    for tenant, resources in expected.items():
        actual = _tenant_resources(sesv2, tenant)
        assert actual == resources, (
            f"{phase}: ListTenantResources({tenant}) returned {sorted(actual)}, expected exactly "
            f"{sorted(resources)}"
        )
    all_resources = {arn for resources in expected.values() for arn in resources}
    for arn in all_resources:
        expected_owners = {t for t, resources in expected.items() if arn in resources}
        actual_owners = _resource_tenants(sesv2, arn) & set(expected)
        assert actual_owners == expected_owners, (
            f"{phase}: ListResourceTenants({arn}) names {sorted(actual_owners)} among this check's "
            f"tenants, but ListTenantResources places it under exactly {sorted(expected_owners)} — "
            f"the two views are not inverses"
        )


def _call_error(fn) -> tuple[str, str]:
    """The (Code, Message) of the ClientError fn() raises; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _safe_delete_tenant(sesv2, name: str) -> None:
    try:
        sesv2.delete_tenant(TenantName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


# Upper bound for retrying a configuration-set delete while SES releases tenant associations,
# one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0


def _safe_delete_configuration_set(sesv2, name: str, arn: str, teardown_deadline) -> None:
    """Teardown: a configuration set that still has tenant associations is refused with
    BadRequestException; its associations are removed first (a deleted tenant's dangling one by
    re-creating that tenant name), then the delete is retried every 2 s to the shared deadline."""
    # A 120 s margin inside that bound, so a teardown raises its own error before the bound runs out.
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
    repaired = False
    while True:
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
            if not in_use or time.monotonic() >= deadline:
                raise
        if not repaired:
            repaired = True
            for tenant in _resource_tenants(sesv2, arn):
                _drop_dangling_association(sesv2, tenant, arn)
        time.sleep(2)


def _drop_dangling_association(sesv2, tenant: str, arn: str) -> None:
    """Remove `tenant`'s association with `arn`; when the tenant is already deleted, re-create it
    under the same name for the removal and delete it again."""
    try:
        sesv2.delete_tenant_resource_association(TenantName=tenant, ResourceArn=arn)
        return
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise
    sesv2.create_tenant(
        TenantName=tenant,
        Tags=[{"Key": "sim2real-managed", "Value": "true"}, {"Key": "sim2real-check", "Value": CHECK}],
    )
    try:
        _safe_delete_association(sesv2, tenant, arn)
    finally:
        _safe_delete_tenant(sesv2, tenant)


def _safe_delete_association(sesv2, tenant: str, resource_arn: str) -> None:
    try:
        sesv2.delete_tenant_resource_association(TenantName=tenant, ResourceArn=resource_arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
