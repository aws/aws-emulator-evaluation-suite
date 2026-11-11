"""create-manager-status-progresses-past-initializing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-manager-status-progresses-past-initializing"
GROUP = "state-machine"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """A new configuration manager's deployment status is always a documented status and moves past INITIALIZING
    within a bounded wait: the deployment state machine advances."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")

    manager_arn = _create_configuration_manager_retrying_role_lag(
        qs,
        Name=ctx.unique_name("sim2real-qs-progress-"),
        ConfigurationDefinitions=[_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
        Tags={"sim2real": CHECK},
    )["ManagerArn"]
    ctx.on_cleanup(lambda: _delete_manager(qs, manager_arn))

    def _deployment_status():
        summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
        entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
        return entry["Status"] if entry else None

    valid_statuses = {
        "INITIALIZING",
        "DEPLOYING",
        "SUCCEEDED",
        "DELETING",
        "STOPPING",
        "FAILED",
        "STOPPED",
        "DELETE_FAILED",
        "STOP_FAILED",
        "NONE",
    }

    deadline = time.monotonic() + 180
    final_status = None
    while time.monotonic() < deadline:
        status = _deployment_status()
        if status is not None:
            assert status in valid_statuses, f"unexpected Status value: {status}"
        if status not in (None, "INITIALIZING"):
            final_status = status
            break
        time.sleep(5)

    assert final_status is not None, "Deployment status never progressed past INITIALIZING"


def _delete_manager(qs, manager_arn: str, timeout: float = 300.0) -> None:
    """Teardown: delete the manager and wait until it is gone, before teardown removes the local
    deployment roles its deletion runs through. A ConflictException (deployment still running) is
    retried; a manager left behind blocks every later manager of its type in the account, so a
    timeout or any other refusal raises."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            qs.delete_configuration_manager(ManagerArn=manager_arn)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() > deadline:
                raise
        time.sleep(5)
    while time.monotonic() < deadline:
        try:
            qs.get_configuration_manager(ManagerArn=manager_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"configuration manager {manager_arn} was not deleted within {timeout}s")


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _latest_type_version(ctx, type_name: str) -> str:
    qs = ctx.client("ssm-quicksetup")
    for t in qs.list_quick_setup_types()["QuickSetupTypeList"]:
        if t["Type"] == type_name:
            return t["LatestVersion"]
    raise AssertionError(f"quick setup type {type_name} not found in ListQuickSetupTypes")


def _create_role_retrying_principal_lag(iam, role_name: str, trust_doc: str, timeout: float = 30.0) -> None:
    """iam.create_role validates that AWS principals named in the trust policy already exist.
    A role created moments ago may not yet be visible to that validation check (IAM propagation
    lag), so retry MalformedPolicyDocument for a bounded window rather than failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_doc,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_configuration_manager_retrying_role_lag(qs, timeout: float = 60.0, **kwargs):
    """CreateConfigurationManager validates the LocalDeployment role ARNs it is handed. A role
    (and its freshly attached policy) created moments ago may not yet be visible to that
    validation (IAM propagation lag), so retry ValidationException for a bounded window instead
    of failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return qs.create_configuration_manager(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ValidationException" or time.monotonic() > deadline:
                raise
            time.sleep(5)


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

    admin_arn = iam.create_role(
        RoleName=admin_name,
        AssumeRolePolicyDocument=admin_trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    _create_role_retrying_principal_lag(iam, exec_name, exec_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    iam.attach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )
    return admin_arn, exec_name


def _host_mgmt_definition(ctx, admin_arn: str, exec_name: str, type_version: str) -> dict:
    # SSMHostMgmt with TargetType="*" targets every instance in the account/region -- an
    # account-wide singleton that ConflictExceptions if another manager already targets it.
    # Scoping to a unique tag keeps each check's deployment non-overlapping.
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
