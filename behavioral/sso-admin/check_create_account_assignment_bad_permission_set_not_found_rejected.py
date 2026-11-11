"""create-account-assignment-bad-permission-set-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-account-assignment-bad-permission-set-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["sso-admin"]

_RESTRICTION = "This operation is not supported for account instances of IAM Identity Center."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """On an IAM Identity Center account instance, CreatePermissionSet, ListPermissionSets, CreateAccountAssignment
    and ListAccountAssignments each fail with ValidationException and the exact restriction message, while
    CreateApplication succeeds."""
    sso = ctx.client("sso-admin")
    instance_arn = _get_instance_arn(ctx)
    instance_id = instance_arn.rsplit("/", 1)[-1]
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    identity_store_id = sso.describe_instance(InstanceArn=instance_arn)["IdentityStoreId"]
    group_id = _create_group(ctx, identity_store_id)

    # Positive control: an ordinary sso-admin write on the same instance succeeds and is
    # visible on an independent read, proving the caller is not broadly
    # denied on this API -- the boundary rejections below are specific to permission sets.
    # Check-owned (its own Application, not shared instance-level state), so it carries no
    # contention risk with concurrent checks against the same shared instance.
    provider_arn = _pick_oauth_provider_arn(ctx)
    app_arn = sso.create_application(
        InstanceArn=instance_arn,
        ApplicationProviderArn=provider_arn,
        Name=ctx.unique_name("sim2real-behav-app-"),
    )["ApplicationArn"]
    ctx.on_cleanup(lambda: sso.delete_application(ApplicationArn=app_arn))
    assert sso.describe_application(ApplicationArn=app_arn)["ApplicationArn"] == app_arn

    # Boundary 1: CreatePermissionSet itself is rejected for an account instance, with the
    # specific account-instance-restriction message -- not a generic validation failure.
    code_ps, msg_ps = _error_code_msg(
        lambda: sso.create_permission_set(Name=ctx.unique_name("sim2real-behav-ps-"), InstanceArn=instance_arn)
    )
    assert code_ps == "ValidationException", (code_ps, msg_ps)
    assert msg_ps == _RESTRICTION, msg_ps
    # Effect absent: ListPermissionSets carries the identical restriction message for account
    # instances (there is no permission-set surface at all), confirming nothing was created.
    code_list, msg_list = _error_code_msg(lambda: sso.list_permission_sets(InstanceArn=instance_arn))
    assert code_list == "ValidationException", (code_list, msg_list)
    assert msg_list == _RESTRICTION, msg_list

    # Boundary 2: CreateAccountAssignment against a syntactically well-formed but nonexistent
    # PermissionSetArn is rejected the same way -- not with ResourceNotFoundException, as
    # the instance-type restriction is checked before the ARN would ever be resolved.
    bogus_ps_arn = f"arn:aws:sso:::permissionSet/{instance_id}/ps-0123456789abcdef"
    code_assign, msg_assign = _error_code_msg(
        lambda: sso.create_account_assignment(
            InstanceArn=instance_arn,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=bogus_ps_arn,
            PrincipalType="GROUP",
            PrincipalId=group_id,
        )
    )
    assert code_assign == "ValidationException", (code_assign, msg_assign)
    assert msg_assign == _RESTRICTION, msg_assign

    # Terminal, independent read at the destination: ListAccountAssignments for the exact
    # (account, bogus permission set) pair carries the identical restriction message rather
    # than an empty result, confirming no assignment request was ever created or queued.
    code_list_assign, msg_list_assign = _error_code_msg(
        lambda: sso.list_account_assignments(
            InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=bogus_ps_arn
        )
    )
    assert code_list_assign == "ValidationException", (code_list_assign, msg_list_assign)
    assert msg_list_assign == _RESTRICTION, msg_list_assign


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


def _pick_oauth_provider_arn(ctx):
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


def _error_code_msg(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
