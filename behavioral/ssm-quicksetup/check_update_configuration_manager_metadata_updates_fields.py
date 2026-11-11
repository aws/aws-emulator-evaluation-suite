"""update-configuration-manager-metadata-updates-fields."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configuration-manager-metadata-updates-fields"
GROUP = "lifecycle"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """Once a manager's deployment has left INITIALIZING/DEPLOYING, UpdateConfigurationManager changes Name and
    Description as GetConfigurationManager shows, and LastModifiedAt does not go backwards."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")
    original_name = ctx.unique_name("sim2real-qs-meta-orig-")

    manager_arn = _create_manager_retrying_role_propagation_lag(
        qs,
        Name=original_name,
        Description="original description",
        ConfigurationDefinitions=[_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
        Tags={"sim2real": CHECK},
    )["ManagerArn"]
    ctx.on_cleanup(lambda: _delete_manager_waiting_out_deployment(qs, manager_arn))

    before = qs.get_configuration_manager(ManagerArn=manager_arn)
    assert before["Name"] == original_name
    assert before["Description"] == "original description"
    last_modified_before = before["LastModifiedAt"]

    settled_status = _wait_for_deployment_to_leave_transitional_states(qs, manager_arn)
    assert settled_status not in ("INITIALIZING", "DEPLOYING")

    updated_name = original_name + "-renamed"
    qs.update_configuration_manager(
        ManagerArn=manager_arn, Name=updated_name, Description="updated description"
    )

    # poll for the update to actually be reflected, rather than assuming it lands instantly
    after = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        after = qs.get_configuration_manager(ManagerArn=manager_arn)
        if after["Name"] == updated_name and after["Description"] == "updated description":
            break
        time.sleep(2)

    assert after is not None
    assert after["Name"] == updated_name
    assert after["Description"] == "updated description"
    assert after["LastModifiedAt"] >= last_modified_before


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _deployment_status(qs, manager_arn: str):
    summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
    entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
    return entry["Status"] if entry else None


def _wait_for_deployment_to_leave_transitional_states(qs, manager_arn: str, timeout: float = 260.0) -> str:
    """UpdateConfigurationManager ConflictExceptions while the manager's own Deployment status is
    still INITIALIZING/DEPLOYING, so a metadata-only update must wait for
    the async deployment to settle before it can land."""
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        status = _deployment_status(qs, manager_arn)
        if status not in (None, "INITIALIZING", "DEPLOYING"):
            return status
        time.sleep(2)
    raise AssertionError(
        f"Deployment status did not leave DEPLOYING within {timeout}s (last status: {status})"
    )


def _delete_manager_waiting_out_deployment(qs, manager_arn: str, timeout: float = 180.0) -> None:
    """DeleteConfigurationManager can ConflictException the same way UpdateConfigurationManager
    does while the manager is still DEPLOYING, so the delete call itself is retried. But
    DeleteConfigurationManager is ALSO asynchronous: it kicks off a teardown that still needs the
    admin/exec IAM roles to be assumable, and this check's own cleanup deletes those roles right
    after this cleanup returns (firing the delete and returning immediately
    races that async teardown against the role cleanups that follow, landing the manager in
    DELETE_FAILED with an AccessDeniedException on a role this check already removed). So this
    waits for the manager to actually disappear before the roles are torn down."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            qs.delete_configuration_manager(ManagerArn=manager_arn)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException":
                raise
            time.sleep(2)
            continue

        while time.monotonic() < deadline:
            try:
                status = _deployment_status(qs, manager_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    return
                raise
            if status == "DELETE_FAILED":
                break  # retry the delete call itself
            time.sleep(2)
        else:
            break
    raise AssertionError(f"{manager_arn} did not finish deleting within {timeout}s")


def _create_manager_retrying_role_propagation_lag(qs, timeout: float = 40.0, **kwargs):
    """CreateConfigurationManager assumes the local deployment roles almost immediately; a role
    attached moments ago may not yet be visible to that cross-service assumption (IAM propagation
    lag), so retry the create for a bounded window rather than a blind pre-sleep."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return qs.create_configuration_manager(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ValidationException") or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _latest_type_version(ctx, type_name: str) -> str:
    qs = ctx.client("ssm-quicksetup")
    for t in qs.list_quick_setup_types()["QuickSetupTypeList"]:
        if t["Type"] == type_name:
            return t["LatestVersion"]
    raise AssertionError(f"quick setup type {type_name} not found in ListQuickSetupTypes")


def _create_role_retrying_principal_lag(
    iam, role_name: str, trust_doc: str, tags: list[dict], timeout: float = 30.0
) -> None:
    """iam.create_role validates that AWS principals named in the trust policy already exist.
    A role created moments ago may not yet be visible to that validation check (IAM propagation
    lag), so retry MalformedPolicyDocument for a bounded window rather than failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc, Tags=tags)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_local_roles(ctx):
    iam = ctx.client("iam")
    admin_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["cloudformation.amazonaws.com", "ssm-quicksetup.amazonaws.com"]},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    admin_name = ctx.unique_name("sim2real-qs-admin-")
    exec_name = ctx.unique_name("sim2real-qs-exec-")

    resource_tags = [{"Key": "sim2real", "Value": CHECK}]
    admin_arn = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=admin_trust, Tags=resource_tags
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    iam.attach_role_policy(RoleName=admin_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=admin_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )

    # the execution role must trust the ADMINISTRATION role (self-managed StackSets model),
    # not a service principal -- Quick Setup's admin role assumes it to deploy resources.
    exec_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    # IAM Principal existence checks on the trust policy can lag the admin role's own creation
    # (eventual consistency), so retry MalformedPolicyDocument for a bounded window.
    _create_role_retrying_principal_lag(iam, exec_name, exec_trust, resource_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    iam.attach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )
    return admin_arn, exec_name


def _host_mgmt_definition(ctx, admin_arn: str, exec_name: str, type_version: str) -> dict:
    # AWSQuickSetupType-SSMHostMgmt is an account+region singleton BY TYPE:
    # CreateConfigurationManager ConflictExceptions ("Found existing resources for type")
    # against ANY other live manager of this type, regardless of TargetTagKey/TargetTagValue --
    # tag-scoping does not create room for a second one to coexist. What actually matters is that
    # at most one manager of this type is alive at a time, so this check's own cleanup deleting
    # what it created (see _delete_manager_waiting_out_deployment) is what keeps the next run
    # unblocked, not the tag scope.
    return {
        "Type": "AWSQuickSetupType-SSMHostMgmt",
        "TypeVersion": type_version,
        "Parameters": {
            "TargetType": "Tags",
            "TargetTagKey": ctx.unique_name("sim2real-behav-qs-key-"),
            "TargetTagValue": ctx.unique_name("sim2real-behav-qs-val-"),
            "TargetAccounts": _account_id(ctx),
            "TargetRegions": ctx.region,
        },
        "LocalDeploymentAdministrationRoleArn": admin_arn,
        "LocalDeploymentExecutionRoleName": exec_name,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
