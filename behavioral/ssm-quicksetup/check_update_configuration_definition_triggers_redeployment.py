"""update-configuration-definition-triggers-redeployment."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configuration-definition-triggers-redeployment"
GROUP = "state-machine"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """UpdateConfigurationDefinition on a settled definition starts a fresh deployment: the
    manager's Deployment status summary passes through INITIALIZING/DEPLOYING before re-settling
    (the manager's LastModifiedAt does not move for a definition update, so status is the signal)."""
    qs = ctx.client("ssm-quicksetup")
    manager_gone = {"confirmed": False}
    admin_arn, exec_name = _create_local_roles(ctx, manager_gone)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")

    manager_arn = qs.create_configuration_manager(
        Name=ctx.unique_name("sim2real-qs-redeploy-"),
        ConfigurationDefinitions=[_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
        Tags={"team": "sim2real", "purpose": "behavioral-check"},
    )["ManagerArn"]

    def _cleanup_manager():
        # DeleteConfigurationManager only *initiates* removal of the underlying self-managed
        # StackSets deployment -- it can take well past this check's own body budget. The
        # deployment administration/execution roles must still exist while that teardown runs,
        # or the StackSet lands in an unrecoverable DELETE_FAILED/INOPERABLE state that
        # permanently blocks this AWSQuickSetupType-SSMHostMgmt slot for the whole account.
        # manager_gone gates the role cleanups below: only delete the roles once the manager
        # itself is confirmed gone, so a slow teardown loses the roles instead of the manager.
        deadline = time.monotonic() + 240
        while True:
            try:
                qs.delete_configuration_manager(ManagerArn=manager_arn)
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    manager_gone["confirmed"] = True
                    return
                if code != "ConflictException" or time.monotonic() > deadline:
                    raise
            time.sleep(2)
        while time.monotonic() < deadline:
            try:
                qs.get_configuration_manager(ManagerArn=manager_arn)
            except ClientError as e:
                if e.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                manager_gone["confirmed"] = True
                return
            time.sleep(2)
        raise AssertionError(f"configuration manager {manager_arn} was not deleted within 240s")

    ctx.on_cleanup(_cleanup_manager)

    def _deployment_status():
        summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
        entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
        return entry["Status"] if entry else None

    # wait for the initial deployment cycle to settle into a non-transient state first, so the
    # update below is not rejected as a concurrent modification of an in-flight deployment
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        status = _deployment_status()
        if status in ("SUCCEEDED", "FAILED"):
            break
        time.sleep(5)
    else:
        raise AssertionError("initial deployment never settled to SUCCEEDED/FAILED")

    before = qs.get_configuration_manager(ManagerArn=manager_arn)
    definition_id = before["ConfigurationDefinitions"][0]["Id"]

    qs.update_configuration_definition(
        ManagerArn=manager_arn,
        Id=definition_id,
        Parameters={
            "TargetType": "Tags",
            "TargetTagKey": ctx.unique_name("sim2real-behav-qs-key-"),
            "TargetTagValue": ctx.unique_name("sim2real-behav-qs-val-"),
        },
    )

    # A settled-then-re-triggered cycle must be OBSERVED passing through a transient state --
    # otherwise a target that just leaves the old terminal status in place (never redeploying at
    # all) would score identically to one that does. Measured on real AWS: the full
    # INITIALIZING -> DEPLOYING -> SUCCEEDED cycle lands within ~20s of the update call.
    deadline = time.monotonic() + 90
    saw_transient = False
    final_status = None
    while time.monotonic() < deadline:
        final_status = _deployment_status()
        if final_status in ("INITIALIZING", "DEPLOYING"):
            saw_transient = True
        elif saw_transient and final_status in ("SUCCEEDED", "FAILED"):
            break
        time.sleep(2)

    assert saw_transient, (
        f"UpdateConfigurationDefinition never moved the deployment through a transient state "
        f"(INITIALIZING/DEPLOYING) -- no fresh redeployment cycle was observed, last status={final_status}"
    )
    assert final_status in ("SUCCEEDED", "FAILED"), (
        f"redeployment triggered by the update did not settle within the window, last status={final_status}"
    )

    # deletion outlasts the teardown budget, and the roles may only go once the manager is gone,
    # so the body deletes the manager itself; the registered teardown covers an early failure.
    deadline = time.monotonic() + 240
    while True:
        try:
            qs.delete_configuration_manager(ManagerArn=manager_arn)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException" or time.monotonic() > deadline:
                raise
        time.sleep(5)
    while True:
        try:
            qs.get_configuration_manager(ManagerArn=manager_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            manager_gone["confirmed"] = True
            break
        if time.monotonic() > deadline:
            raise AssertionError(f"configuration manager {manager_arn} was not deleted within 240s")
        time.sleep(5)


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _latest_type_version(ctx, type_name: str) -> str:
    qs = ctx.client("ssm-quicksetup")
    for t in qs.list_quick_setup_types()["QuickSetupTypeList"]:
        if t["Type"] == type_name:
            return t["LatestVersion"]
    raise AssertionError(f"quick setup type {type_name} not found in ListQuickSetupTypes")


def _wait_for_policy_attached(iam, role_name: str, policy_arn: str, timeout: float = 60.0) -> None:
    """attach_role_policy's own eventual consistency means the attachment may not yet be
    visible to a subsequent read -- and Quick Setup resolves these roles by name/ARN shortly
    after this call returns. Poll the attachment itself instead of guessing a fixed delay."""
    deadline = time.monotonic() + timeout
    while True:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        if any(p["PolicyArn"] == policy_arn for p in attached):
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"{policy_arn} never appeared attached to role {role_name}")
        time.sleep(3)


_ROLE_TAGS = [{"Key": "team", "Value": "sim2real"}, {"Key": "purpose", "Value": "behavioral-check"}]


def _create_role_retrying_principal_lag(iam, role_name: str, trust_doc: str, timeout: float = 30.0) -> None:
    """iam.create_role validates that AWS principals named in the trust policy already exist.
    A role created moments ago may not yet be visible to that validation check (IAM propagation
    lag), so retry MalformedPolicyDocument for a bounded window instead of failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc, Tags=_ROLE_TAGS)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_local_roles(ctx, manager_gone: dict):
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

    def _delete_role_once_manager_gone(role_name: str) -> None:
        # See _cleanup_manager: deleting this role before the StackSet teardown that depends on
        # it finishes strands the deployment permanently. Leaving the role behind is the cheap,
        # reapable failure mode; deleting it too early is the expensive, unreapable one.
        if manager_gone["confirmed"]:
            iam.delete_role(RoleName=role_name)

    def _detach_once_manager_gone(role_name: str, policy_arn: str) -> None:
        if manager_gone["confirmed"]:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    admin_policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    admin_arn = iam.create_role(
        RoleName=admin_name, AssumeRolePolicyDocument=admin_trust, Tags=_ROLE_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role_once_manager_gone(admin_name))
    iam.attach_role_policy(RoleName=admin_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: _detach_once_manager_gone(admin_name, admin_policy_arn))
    _wait_for_policy_attached(iam, admin_name, admin_policy_arn)

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
    ctx.on_cleanup(lambda: _delete_role_once_manager_gone(exec_name))
    iam.attach_role_policy(RoleName=exec_name, PolicyArn=admin_policy_arn)
    ctx.on_cleanup(lambda: _detach_once_manager_gone(exec_name, admin_policy_arn))
    _wait_for_policy_attached(iam, exec_name, admin_policy_arn)
    return admin_arn, exec_name


def _host_mgmt_definition(ctx, admin_arn: str, exec_name: str, type_version: str) -> dict:
    # AWSQuickSetupType-SSMHostMgmt is a strict per-account/region singleton: CreateConfigurationManager
    # ConflictExceptions ("Found existing resources for type: ...") whenever ANY manager of this type
    # already exists, regardless of TargetType/tag scoping.
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
