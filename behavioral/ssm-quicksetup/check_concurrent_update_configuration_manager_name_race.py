"""concurrent-update-configuration-manager-name-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-configuration-manager-name-race"
GROUP = "concurrency"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """Two concurrent UpdateConfigurationManager renames of one manager each succeed or fail with ConflictException
    or ThrottlingException, at least one succeeds, and the final Name is exactly one of the two names."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")

    manager_arn = _create_configuration_manager_retrying_role_propagation(
        qs,
        ctx.unique_name("sim2real-qs-race-"),
        [_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
        tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: _delete_manager(qs, manager_arn))

    # UpdateConfigurationManager is a ConflictException while the deployment is in progress, so
    # the race starts once the manager has settled.
    _wait_past_deploying(ctx, manager_arn)

    name_a = ctx.unique_name("sim2real-qs-race-a-")
    name_b = ctx.unique_name("sim2real-qs-race-b-")
    acceptable_error_codes = {"ConflictException", "ThrottlingException"}

    def _attempt(name):
        try:
            qs.update_configuration_manager(ManagerArn=manager_arn, Name=name)
            return ("ok", name)
        except ClientError as e:
            return (e.response["Error"]["Code"], name)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_attempt, [name_a, name_b]))

    for code, name in results:
        assert code == "ok" or code in acceptable_error_codes, (
            f"racer for {name!r} got unexpected error code {code!r}"
        )
    assert any(code == "ok" for code, _ in results), "neither concurrent update succeeded"

    final_name = qs.get_configuration_manager(ManagerArn=manager_arn)["Name"]
    assert final_name in (name_a, name_b), f"final Name {final_name!r} is neither racer's value"


def _wait_past_deploying(ctx, manager_arn: str, timeout: float = 180.0) -> None:
    qs = ctx.client("ssm-quicksetup")
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
        entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
        status = entry["Status"] if entry else None
        if status not in (None, "INITIALIZING", "DEPLOYING"):
            return
        time.sleep(5)
    raise AssertionError(f"manager {manager_arn} deployment status never left DEPLOYING (last={status})")


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
    window rather than a blind sleep before the roles are ever used."""
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
