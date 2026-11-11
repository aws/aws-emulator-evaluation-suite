"""create-configuration-manager-invalid-name-pattern-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-configuration-manager-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-quicksetup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """CreateConfigurationManager rejects a Name containing characters outside
    `[ A-Za-z0-9._-]` with ValidationException, creates no manager as a side effect, and the same
    call with a pattern-valid name (positive control, same file) succeeds."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")
    invalid_name = ctx.unique_name("sim2real-qs-badname-") + "!!!"

    err = _client_error(
        lambda: _create_configuration_manager_retrying_role_propagation(
            qs,
            invalid_name,
            [_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
            tags={"sim2real-check": CHECK},
        )
    )
    code = err.get("Code")
    assert code == "ValidationException", f"expected ValidationException for Name={invalid_name!r}, got {code!r}"
    expected_message = (
        f"1 validation error detected: Value '{invalid_name}' at 'name' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [ A-Za-z0-9._-]{0,120}"
    )
    assert err.get("Message") == expected_message, f"expected {expected_message!r}, got {err.get('Message')!r}"

    found = False
    token = None
    for _ in range(20):
        kwargs = {"MaxItems": 100}
        if token:
            kwargs["StartingToken"] = token
        page = qs.list_configuration_managers(**kwargs)
        if any(m.get("Name") == invalid_name for m in page["ConfigurationManagersList"]):
            found = True
            break
        token = page.get("NextToken")
        if not token:
            break
    assert not found, "a manager was created despite the rejected invalid Name"

    valid_name = ctx.unique_name("sim2real-qs-goodname-")
    manager_arn = _create_configuration_manager_retrying_role_propagation(
        qs,
        valid_name,
        [_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_manager(qs, manager_arn))
    got_name = qs.get_configuration_manager(ManagerArn=manager_arn)["Name"]
    assert got_name == valid_name, f"expected Name={valid_name!r} on the created manager, got {got_name!r}"
    # deletion outlasts the teardown budget and needs the deployment roles teardown removes, so
    # the body deletes the manager itself; the registered teardown covers an early failure.
    _delete_manager(qs, manager_arn, timeout=240.0)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_manager(qs, manager_arn: str, timeout: float = 45.0) -> None:
    """Teardown only: delete the manager and wait until it is gone, because deletion runs through
    the local deployment roles and fails for good once teardown removes them. A ConflictException
    (deployment still running) is retried; a manager left behind blocks every later manager of its
    type in the account, so a timeout or any other refusal raises."""
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
    lag), so retry MalformedPolicyDocument for a bounded window instead of failing outright."""
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
        RoleName=admin_name, AssumeRolePolicyDocument=admin_trust, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
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
    iam.tag_role(RoleName=exec_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=exec_name))
    iam.attach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=exec_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )
    return admin_arn, exec_name


def _create_configuration_manager_retrying_role_propagation(
    qs, name: str, definitions: list, tags: dict, timeout: float = 60.0
) -> str:
    """The local deployment roles were just created; ssm-quicksetup's own validation of those
    role ARNs can lag IAM's eventual consistency, so retry a role-shaped rejection for a bounded
    window instead of a blind sleep before the roles are ever used."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return qs.create_configuration_manager(Name=name, ConfigurationDefinitions=definitions, Tags=tags)[
                "ManagerArn"
            ]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "").lower()
            role_shaped = code == "AccessDeniedException" or (
                code == "ValidationException" and ("role" in message or "assume" in message)
            )
            if not role_shaped or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _host_mgmt_definition(ctx, admin_arn: str, exec_name: str, type_version: str) -> dict:
    # AWSQuickSetupType-SSMHostMgmt is an account/region-wide singleton by Type: at most one
    # configuration manager of this Type may exist at a time, and CreateConfigurationManager
    # ConflictExceptions otherwise regardless of TargetType/tag scoping -- scoping narrows which
    # instances the deployment targets, not the manager's identity.
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
