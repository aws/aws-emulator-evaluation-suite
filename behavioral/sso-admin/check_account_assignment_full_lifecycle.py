"""account-assignment-full-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-assignment-full-lifecycle"
GROUP = "state"
SERVICES = ["sso-admin"]

_ACCOUNT_INSTANCE_MESSAGE = "This operation is not supported for account instances of IAM Identity Center."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:identity-center-instance")
def run(ctx) -> None:
    """On an IAM Identity Center account instance, Create and DeleteAccountAssignment, both assignment status reads
    and ListAccountAssignments each fail with ValidationException and the exact account-instance message, while
    ListInstances lists the instance."""
    sso = ctx.client("sso-admin")
    idstore = ctx.client("identitystore")
    instance_arn = _get_instance_arn(ctx)
    instance_id = instance_arn.rsplit("/", 1)[-1]
    identity_store_id = sso.describe_instance(InstanceArn=instance_arn)["IdentityStoreId"]

    # Positive control: the instance and identity store are reachable and healthy: this is
    # not a blanket outage, only the permission-set/account-assignment surface is withdrawn.
    instance_arns = [i["InstanceArn"] for i in sso.list_instances()["Instances"]]
    assert instance_arn in instance_arns, (instance_arn, instance_arns)
    group_id = idstore.create_group(
        IdentityStoreId=identity_store_id, DisplayName=ctx.unique_name("sim2real-behav-group-")
    )["GroupId"]
    ctx.on_cleanup(lambda: idstore.delete_group(IdentityStoreId=identity_store_id, GroupId=group_id))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    # Syntactically well-formed, deliberately nonexistent -- no real PermissionSetArn can ever
    # exist on an account instance, so this stands in for "any" permission set.
    bogus_ps_arn = f"arn:aws:sso:::permissionSet/{instance_id}/ps-0123456789abcdef"
    bogus_request_id = "00000000-0000-0000-0000-000000000000"

    create_code, create_msg = _error(
        lambda: sso.create_account_assignment(
            InstanceArn=instance_arn,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=bogus_ps_arn,
            PrincipalType="GROUP",
            PrincipalId=group_id,
        )
    )
    assert create_code == "ValidationException", create_code
    assert create_msg == _ACCOUNT_INSTANCE_MESSAGE, create_msg

    delete_code, delete_msg = _error(
        lambda: sso.delete_account_assignment(
            InstanceArn=instance_arn,
            TargetId=account_id,
            TargetType="AWS_ACCOUNT",
            PermissionSetArn=bogus_ps_arn,
            PrincipalType="GROUP",
            PrincipalId=group_id,
        )
    )
    assert delete_code == "ValidationException", delete_code
    assert delete_msg == _ACCOUNT_INSTANCE_MESSAGE, delete_msg

    creation_status_code, creation_status_msg = _error(
        lambda: sso.describe_account_assignment_creation_status(
            InstanceArn=instance_arn, AccountAssignmentCreationRequestId=bogus_request_id
        )
    )
    assert creation_status_code == "ValidationException", creation_status_code
    assert creation_status_msg == _ACCOUNT_INSTANCE_MESSAGE, creation_status_msg

    deletion_status_code, deletion_status_msg = _error(
        lambda: sso.describe_account_assignment_deletion_status(
            InstanceArn=instance_arn, AccountAssignmentDeletionRequestId=bogus_request_id
        )
    )
    assert deletion_status_code == "ValidationException", deletion_status_code
    assert deletion_status_msg == _ACCOUNT_INSTANCE_MESSAGE, deletion_status_msg

    # Effect-absent, at the destination: ListAccountAssignments itself is rejected the same
    # way -- there is no account-assignment surface to list on an account instance, which is
    # itself confirmation that none of the calls above ever created anything.
    list_code, list_msg = _error(
        lambda: sso.list_account_assignments(
            InstanceArn=instance_arn, AccountId=account_id, PermissionSetArn=bogus_ps_arn
        )
    )
    assert list_code == "ValidationException", list_code
    assert list_msg == _ACCOUNT_INSTANCE_MESSAGE, list_msg


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
