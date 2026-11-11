"""local-deployment-missing-role-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "local-deployment-missing-role-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-quicksetup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """A TargetAccounts deployment without LocalDeploymentAdministrationRoleArn and LocalDeploymentExecutionRoleName
    fails with ValidationException and the exact message and creates no manager, while the same definition with both
    roles succeeds."""
    qs = ctx.client("ssm-quicksetup")
    account_id = _account_id(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")
    probe_name = ctx.unique_name("sim2real-qs-norole-")

    incomplete_definition = {
        "Type": "AWSQuickSetupType-SSMHostMgmt",
        "TypeVersion": type_version,
        "Parameters": {
            "TargetType": "Tags",
            "TargetTagKey": ctx.unique_name("sim2real-behav-qs-key-"),
            "TargetTagValue": ctx.unique_name("sim2real-behav-qs-val-"),
            "TargetAccounts": account_id,
            "TargetRegions": ctx.region,
        },
    }

    try:
        accepted = qs.create_configuration_manager(
            Name=probe_name, ConfigurationDefinitions=[incomplete_definition]
        )
    except ClientError as exc:
        error = exc.response["Error"]
    else:
        ctx.on_cleanup(lambda: _delete_manager(qs, accepted["ManagerArn"]))
        raise AssertionError(
            f"expected ValidationException, but CreateConfigurationManager SUCCEEDED and returned {accepted!r}"
        )
    code, message = error.get("Code"), error.get("Message")
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = "The required parameter LocalDeploymentAdministrationRoleArn is missing."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    found = False
    token = None
    for _ in range(20):
        kwargs = {"MaxItems": 100}
        if token:
            kwargs["StartingToken"] = token
        page = qs.list_configuration_managers(**kwargs)
        if any(m.get("Name") == probe_name for m in page["ConfigurationManagersList"]):
            found = True
            break
        token = page.get("NextToken")
        if not token:
            break
    assert not found, "a manager was created despite missing local deployment roles"

    # positive control: same definition, with local deployment roles supplied
    admin_arn, exec_name = _create_local_roles(ctx)
    complete_definition = dict(incomplete_definition)
    complete_definition["LocalDeploymentAdministrationRoleArn"] = admin_arn
    complete_definition["LocalDeploymentExecutionRoleName"] = exec_name

    manager_arn = _create_configuration_manager_retrying_role_propagation(
        qs, probe_name, [complete_definition]
    )["ManagerArn"]
    ctx.on_cleanup(lambda: _delete_manager(qs, manager_arn))
    assert qs.get_configuration_manager(ManagerArn=manager_arn)["Name"] == probe_name


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


def _best_effort(fn) -> None:
    """Run a teardown call whose failure must not mask the check's own result."""
    try:
        fn()
    except ClientError:
        pass


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

    admin_arn = iam.create_role(RoleName=admin_name, AssumeRolePolicyDocument=admin_trust)["Role"]["Arn"]
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


def _create_configuration_manager_retrying_role_propagation(qs, name: str, definitions, timeout: float = 60.0):
    """The roles just created (and the policies just attached to them) may not yet be visible to
    Quick Setup's own role validation (IAM eventual consistency), so retry the specific
    role-rejection error for a bounded window rather than sleeping blindly beforehand."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return qs.create_configuration_manager(Name=name, ConfigurationDefinitions=definitions)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ValidationException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
