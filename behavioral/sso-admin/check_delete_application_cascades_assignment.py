"""delete-application-cascades-assignment."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-application-cascades-assignment"
GROUP = "state-machine"
SERVICES = ["sso-admin"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """DeleteApplication succeeds while a group assignment exists, after which DescribeApplication,
    DescribeApplicationAssignment and CreateApplicationAssignment all fail with ResourceNotFoundException "No
    resource found for application arn: <arn>"."""
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
    ctx.on_cleanup(lambda: _safe(lambda: sso.delete_application(ApplicationArn=app_arn)))

    sso.create_application_assignment(ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP")
    assignment = sso.describe_application_assignment(
        ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP"
    )
    assert assignment["PrincipalId"] == group_id, (
        f"expected the fresh assignment's PrincipalId to be {group_id!r}, got {assignment['PrincipalId']!r}"
    )

    # No conflict: the application deletes cleanly despite the still-present assignment.
    sso.delete_application(ApplicationArn=app_arn)

    code_app, msg_app = _error(lambda: sso.describe_application(ApplicationArn=app_arn))
    assert code_app == "ResourceNotFoundException", (
        f"expected DescribeApplication on the deleted application to raise ResourceNotFoundException, got {code_app!r}"
    )
    assert msg_app == f"No resource found for application arn: {app_arn}", msg_app

    # The dependent assignment does not silently survive its deleted parent application.
    code_assignment, msg_assignment = _error(
        lambda: sso.describe_application_assignment(
            ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP"
        )
    )
    assert code_assignment == "ResourceNotFoundException", (
        f"expected DescribeApplicationAssignment on the deleted application's dependent assignment to raise "
        f"ResourceNotFoundException, got {code_assignment!r}"
    )
    assert msg_assignment == f"No resource found for application arn: {app_arn}", msg_assignment

    # The dead application id is not just unreadable -- it also rejects a mutation, proving it is
    # fully gone rather than merely hidden from Describe.
    code_recreate, msg_recreate = _error(
        lambda: sso.create_application_assignment(
            ApplicationArn=app_arn, PrincipalId=group_id, PrincipalType="GROUP"
        )
    )
    assert code_recreate == "ResourceNotFoundException", (
        f"expected CreateApplicationAssignment against the deleted application {app_arn} to raise "
        f"ResourceNotFoundException, got {code_recreate!r}"
    )
    assert msg_recreate == f"No resource found for application arn: {app_arn}", msg_recreate


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
    accepts a call AWS refuses fails loudly rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
