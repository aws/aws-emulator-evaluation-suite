"""update-configuration-definition-invalid-type-version-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-configuration-definition-invalid-type-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-quicksetup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """UpdateConfigurationDefinition rejects a TypeVersion outside the `\\d{1,3}(\\.\\d{1,3})?` /
    `LATEST` shape with ValidationException and leaves TypeVersion unchanged, while updating to
    `LATEST` succeeds and resolves to the type's current concrete version, never echoing `LATEST`."""
    qs = ctx.client("ssm-quicksetup")
    manager_state: dict = {}
    admin_arn, exec_name = _create_local_roles(ctx, qs, manager_state)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")

    manager_arn = _create_manager_retrying_role_propagation(
        qs,
        ctx.unique_name("sim2real-qs-badtypever-"),
        [_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
    )["ManagerArn"]
    manager_state["manager_arn"] = manager_arn
    ctx.on_cleanup(lambda: _delete_manager(qs, manager_arn))

    def _deployment_status():
        summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
        entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
        return entry["Status"] if entry else None

    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        if _deployment_status() in ("SUCCEEDED", "FAILED"):
            break
        time.sleep(5)
    else:
        raise AssertionError("initial deployment never settled to SUCCEEDED/FAILED")

    manager = qs.get_configuration_manager(ManagerArn=manager_arn)
    definition_id = manager["ConfigurationDefinitions"][0]["Id"]

    err = _client_error(
        lambda: qs.update_configuration_definition(
            ManagerArn=manager_arn, Id=definition_id, TypeVersion="not-a-version"
        )
    )
    code = err.get("Code")
    assert code == "ValidationException", f"expected ValidationException for a malformed TypeVersion, got {code!r}"
    expected_message = (
        "1 validation error detected: Value 'not-a-version' at 'typeVersion' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: \\d{1,3}(\\.\\d{1,3})?$|^LATEST"
    )
    assert err.get("Message") == expected_message, f"expected {expected_message!r}, got {err.get('Message')!r}"

    unchanged_version = qs.get_configuration_manager(ManagerArn=manager_arn)["ConfigurationDefinitions"][0]["TypeVersion"]
    assert unchanged_version == type_version, (
        f"rejected update must leave TypeVersion unchanged: expected {type_version!r}, got {unchanged_version!r}"
    )

    # positive control: LATEST is an accepted TypeVersion literal -- the service resolves it to
    # the type's current latest concrete version rather than echoing the literal back (confirmed
    # against real AWS: GetConfigurationManager never returns "LATEST" itself).
    qs.update_configuration_definition(ManagerArn=manager_arn, Id=definition_id, TypeVersion="LATEST")
    after_version = qs.get_configuration_manager(ManagerArn=manager_arn)["ConfigurationDefinitions"][0]["TypeVersion"]
    assert after_version == type_version, (
        f"TypeVersion='LATEST' must resolve to the type's current latest version {type_version!r}, got {after_version!r}"
    )

    # the LATEST update starts a redeployment that refuses DeleteConfigurationManager with
    # ConflictException and outlasts the teardown budget, so the body deletes the manager itself;
    # the registered teardown covers an early failure.
    deadline = time.monotonic() + 240
    while True:
        try:
            qs.delete_configuration_manager(ManagerArn=manager_arn)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "ConflictException" or time.monotonic() > deadline:
                raise
        time.sleep(5)
    while not _manager_is_gone(qs, manager_arn):
        if time.monotonic() > deadline:
            raise AssertionError(f"configuration manager {manager_arn} was not deleted within 240s")
        time.sleep(5)


# ===== helpers =====


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses must not be reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _latest_type_version(ctx, type_name: str) -> str:
    qs = ctx.client("ssm-quicksetup")
    for t in qs.list_quick_setup_types()["QuickSetupTypeList"]:
        if t["Type"] == type_name:
            return t["LatestVersion"]
    raise AssertionError(f"quick setup type {type_name} not found in ListQuickSetupTypes")


def _create_role_retrying_principal_lag(
    iam, role_name: str, trust_doc: str, role_tags=None, timeout: float = 30.0
) -> None:
    """iam.create_role validates that AWS principals named in the trust policy already exist.
    A role created moments ago may not yet be visible to that validation check (IAM propagation
    lag), so retry MalformedPolicyDocument for a bounded window instead of failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc, Tags=role_tags or [])
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_local_roles(ctx, qs, manager_state: dict):
    iam = ctx.client("iam")
    role_tags = [{"Key": "sim2real-check", "Value": CHECK}]
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

    admin_arn = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=admin_trust, Tags=role_tags)["Role"]["Arn"]
    # Quick Setup's own async teardown of what it deployed must assume this role; delete it only
    # once the manager cleanup (registered later, so it runs first -- cleanups are LIFO) has
    # actually finished, never unconditionally. See _delete_role_once_manager_is_gone.
    ctx.on_cleanup(lambda: _delete_role_once_manager_is_gone(iam, qs, manager_state, admin_name, budget=45.0))
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
    _create_role_retrying_principal_lag(iam, exec_name, exec_trust, role_tags=role_tags)
    ctx.on_cleanup(lambda: _delete_role_once_manager_is_gone(iam, qs, manager_state, exec_name, budget=10.0))
    iam.attach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )
    return admin_arn, exec_name


def _create_manager_retrying_role_propagation(qs, name: str, definitions: list, timeout: float = 60.0):
    """The admin/execution roles' policy attachments may not yet be visible to Quick Setup's
    own role-assumption check moments after IAM applies them (cross-service eventual
    consistency), so retry the specific failure that causes for a bounded window instead of
    sleeping blindly beforehand."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return qs.create_configuration_manager(Name=name, ConfigurationDefinitions=definitions)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ValidationException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _delete_manager(qs, manager_arn: str) -> None:
    try:
        qs.delete_configuration_manager(ManagerArn=manager_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _manager_is_gone(qs, manager_arn: str) -> bool:
    try:
        qs.get_configuration_manager(ManagerArn=manager_arn)
        return False
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise


def _delete_role_once_manager_is_gone(iam, qs, manager_state: dict, role_name: str, budget: float) -> None:
    """Quick Setup's async teardown of what it deployed must assume this local role, so deleting
    it while that teardown is still in flight strands the manager DELETING with no role left that
    can finish removing it -- observed on real AWS as AccessDeniedException("Role ... can't be
    accessed") on a manager that can then never be deleted. The manager's own delete cleanup runs
    first (cleanups are LIFO), so poll here, within our slice of the shared 60s cleanup budget,
    for it to actually disappear before deleting the role. If it is still tearing down when the
    budget runs out, leave the role (cheap and tagged) rather than orphan the manager."""
    manager_arn = manager_state.get("manager_arn")
    deadline = time.monotonic() + budget
    while manager_arn and not _manager_is_gone(qs, manager_arn):
        if time.monotonic() > deadline:
            return
        time.sleep(5)
    iam.delete_role(RoleName=role_name)


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
