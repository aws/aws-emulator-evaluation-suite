"""configuration-manager-create-get-delete-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-manager-create-get-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """A created configuration manager has a configuration-manager ARN, GetConfigurationManager returns its Name,
    Description and one Distributor definition, ListConfigurationManagers shows it, and after delete
    GetConfigurationManager fails with ResourceNotFoundException and the exact not-found message."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    name = ctx.unique_name("sim2real-qs-lifecycle-")

    resp = _create_manager_retrying_role_propagation(
        qs,
        Name=name,
        Description="sim2real behavioral lifecycle check",
        ConfigurationDefinitions=[_distributor_definition(ctx, admin_arn, exec_name)],
    )
    manager_arn = resp["ManagerArn"]
    assert manager_arn.startswith("arn:aws:ssm-quicksetup:") and "configuration-manager/" in manager_arn

    def _cleanup_delete():
        # The body deletes the manager, so the wait's GetConfigurationManager or the delete
        # answers ResourceNotFoundException: already gone.
        try:
            try:
                _wait_past_deploying(qs, manager_arn, timeout=45.0)
            except AssertionError:
                pass
            qs.delete_configuration_manager(ManagerArn=manager_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_delete)

    got = qs.get_configuration_manager(ManagerArn=manager_arn)
    assert got["Name"] == name
    assert got["Description"] == "sim2real behavioral lifecycle check"
    assert len(got["ConfigurationDefinitions"]) == 1
    assert got["ConfigurationDefinitions"][0]["Type"] == "AWSQuickSetupType-Distributor"

    found = False
    token = None
    for _ in range(20):
        kwargs = {"MaxItems": 100}
        if token:
            kwargs["StartingToken"] = token
        page = qs.list_configuration_managers(**kwargs)
        if any(m["ManagerArn"] == manager_arn for m in page["ConfigurationManagersList"]):
            found = True
            break
        token = page.get("NextToken")
        if not token:
            break
    assert found, "created manager was not visible in ListConfigurationManagers"

    _wait_past_deploying(qs, manager_arn)
    qs.delete_configuration_manager(ManagerArn=manager_arn)

    deadline = time.monotonic() + 120
    last_code = None
    last_message = None
    while time.monotonic() < deadline:
        try:
            qs.get_configuration_manager(ManagerArn=manager_arn)
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            last_message = e.response["Error"].get("Message")
            if last_code == "ResourceNotFoundException":
                break
            raise
        time.sleep(3)
    assert last_code == "ResourceNotFoundException", (
        f"manager was not removed within timeout, last GetConfigurationManager error: {last_code}"
    )
    assert last_message == f"Quick setup manager with arn: {manager_arn} could not be found.", last_message


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _wait_past_deploying(qs, manager_arn: str, timeout: float = 180.0) -> None:
    """DeleteConfigurationManager is rejected with ConflictException while the manager's
    Deployment status is still DEPLOYING, so wait for the async
    orchestration to leave that state before attempting delete."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
        entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
        status = entry["Status"] if entry else None
        if status not in ("INITIALIZING", "DEPLOYING"):
            return
        time.sleep(5)
    raise AssertionError("configuration manager did not leave DEPLOYING within timeout")


def _create_manager_retrying_role_propagation(qs, timeout: float = 120.0, **kwargs) -> dict:
    """CreateConfigurationManager validates that the local-deployment roles it was handed exist
    and are assumable. A role created moments ago may not yet be visible to that validation
    (IAM propagation lag), so retry a role-related refusal for a bounded window rather than
    failing outright.

    A configuration manager of a given QuickSetupType is also an account/region-wide singleton
    -- ConflictException("Found existing resources for type: ...") regardless of target scoping
    -- for both AWSQuickSetupType-SSMHostMgmt and AWSQuickSetupType-Distributor.
    That conflict is contention from another manager of this type
    (another run of this check, or a concurrently running check) rather than this
    check's own resource, so it is waited out, never deleted -- deleting a same-typed manager
    this check did not itself just create could tear down a concurrently-running check's live
    deployment."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return qs.create_configuration_manager(**kwargs)
        except ClientError as e:
            message = e.response["Error"].get("Message", "")
            is_retryable = "role" in message.lower() or "Found existing resources for type" in message
            if not is_retryable or time.monotonic() > deadline:
                raise
            time.sleep(5)


def _create_role_retrying_principal_lag(iam, role_name: str, trust_doc: str, timeout: float = 30.0) -> None:
    """iam.create_role validates that AWS principals named in the trust policy already exist.
    A role created moments ago may not yet be visible to that validation check (IAM propagation
    lag), so retry MalformedPolicyDocument for a bounded window rather than failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_local_roles(ctx):
    """Creates a throwaway IAM administration + execution role pair usable as the
    LocalDeploymentAdministrationRoleArn / LocalDeploymentExecutionRoleName required by Quick
    Setup for any single-account (local) configuration deployment. This mirrors the self-managed
    CloudFormation StackSets permission model Quick Setup uses under the hood: the
    administration role trusts cloudformation.amazonaws.com / ssm-quicksetup.amazonaws.com, and
    the execution role trusts the administration role (not a service principal)."""
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

    admin_arn = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=admin_trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    iam.attach_role_policy(RoleName=admin_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=admin_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )

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


def _distributor_definition(ctx, admin_arn: str, exec_name: str) -> dict:
    # Every QuickSetupType is an account/region-wide singleton -- ConflictException("Found
    # existing resources for type: ...") regardless of TargetType/tag scoping --
    # for both AWSQuickSetupType-SSMHostMgmt and AWSQuickSetupType-Distributor.
    # Distributor is used here (over SSMHostMgmt) only because it needs no type-version lookup
    # ("LATEST" is accepted directly); the singleton hazard is handled by
    # _create_manager_retrying_role_propagation's adopt-and-retry, not by this choice of type.
    return {
        "Type": "AWSQuickSetupType-Distributor",
        "TypeVersion": "LATEST",
        "Parameters": {
            "PackagesToInstall": "AWSEC2LaunchAgent",
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
