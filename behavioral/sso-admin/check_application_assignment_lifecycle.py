"""application-assignment-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-assignment-lifecycle"
GROUP = "state"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """CreateApplicationAssignment makes the principal show up in DescribeApplicationAssignment
    and ListApplicationAssignments, and DeleteApplicationAssignment removes it (subsequent
    Describe raises ResourceNotFoundException)."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    provider_arn = _pick_application_provider_arn(ctx)
    identity_store_id = sso.describe_instance(InstanceArn=instance_arn)["IdentityStoreId"]
    group_id = _create_group(ctx, identity_store_id)

    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))

    sso.create_application_assignment(ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP")

    described = sso.describe_application_assignment(
        ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP"
    )
    assert described["PrincipalId"] == group_id, (
        f"expected DescribeApplicationAssignment to report PrincipalId={group_id!r}, got {described['PrincipalId']!r}"
    )
    assert described["PrincipalType"] == "GROUP", (
        f"expected DescribeApplicationAssignment to report PrincipalType='GROUP', got {described['PrincipalType']!r}"
    )

    listed = sso.list_application_assignments(ApplicationArn=app_arn)["ApplicationAssignments"]
    assert any(a["PrincipalId"] == group_id for a in listed), (
        f"expected group {group_id!r} in ListApplicationAssignments for {app_arn!r}, got principals "
        f"{[a['PrincipalId'] for a in listed]!r}"
    )

    by_principal = sso.list_application_assignments_for_principal(
        InstanceArn=instance_arn, PrincipalId=group_id, PrincipalType="GROUP"
    )["ApplicationAssignments"]
    assert any(a["ApplicationArn"] == app_arn for a in by_principal), (
        f"expected application {app_arn!r} in ListApplicationAssignmentsForPrincipal for group "
        f"{group_id!r}, got applications {[a['ApplicationArn'] for a in by_principal]!r}"
    )

    sso.delete_application_assignment(ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP")

    code, message = _error(
        lambda: sso.describe_application_assignment(
            ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP"
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected DescribeApplicationAssignment on the deleted assignment to raise "
        f"ResourceNotFoundException, got {code!r}"
    )
    assert message == "", message

    redelete_code, redelete_msg = _error(
        lambda: sso.delete_application_assignment(
            ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP"
        )
    )
    assert redelete_code == "ResourceNotFoundException", (
        f"expected DeleteApplicationAssignment on the already-deleted assignment to raise "
        f"ResourceNotFoundException, got {redelete_code!r}"
    )
    assert redelete_msg == "", redelete_msg


def _get_instance_arn(ctx):
    import time

    sso = ctx.client("sso-admin")
    instances = sso.list_instances().get("Instances", [])
    if instances:
        instance_arn = instances[0]["InstanceArn"]
    else:
        instance_arn = sso.create_instance()["InstanceArn"]
    deadline = time.time() + 120
    status = None
    while time.time() < deadline:
        status = sso.describe_instance(InstanceArn=instance_arn)["Status"]
        if status == "ACTIVE":
            return instance_arn
        if status in ("CREATE_FAILED", "DELETE_IN_PROGRESS"):
            raise RuntimeError(f"IAM Identity Center instance in unexpected state: {status}")
        time.sleep(3)
    raise RuntimeError(f"IAM Identity Center instance did not become ACTIVE in time (last status: {status})")


def _pick_application_provider_arn(ctx):

    sso = ctx.client("sso-admin")
    providers = {p["ApplicationProviderArn"] for p in sso.list_application_providers().get("ApplicationProviders", [])}
    custom_arn = "arn:aws:sso::aws:applicationProvider/custom"
    if custom_arn not in providers:
        raise AssertionError("the generic customer-managed OAuth2 application provider is not available in this partition")
    return custom_arn


def _create_group(ctx, identity_store_id):
    idstore = ctx.client("identitystore")
    group_id = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id))
    return group_id


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises, so a target that
    accepts a call AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
