"""access-denied-without-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "access-denied-without-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-quicksetup"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """A principal whose policy explicitly denies ssm-quicksetup:GetConfigurationManager gets AccessDeniedException
    with the exact denial message, yet still lists that manager, and the unrestricted caller still reads it: the
    deny is scoped to the one action."""
    qs = ctx.client("ssm-quicksetup")
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    account_id = _account_id(ctx)

    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")
    manager_name = ctx.unique_name("sim2real-qs-denytest-")
    manager_definition = _host_mgmt_definition(ctx, admin_arn, exec_name, type_version)

    # the roles just created may not yet be visible to Quick Setup's own role-assumability
    # validation (cross-service IAM propagation lag), so retry a transient rejection to a bounded
    # deadline rather than sleeping a fixed duration up front.
    deadline = time.monotonic() + 60
    manager_arn = None
    last_create_error = None
    while time.monotonic() < deadline:
        try:
            manager_arn = qs.create_configuration_manager(
                Name=manager_name,
                ConfigurationDefinitions=[manager_definition],
                Tags={"sim2real-check": CHECK},
            )["ManagerArn"]
            break
        except ClientError as e:
            last_create_error = e.response["Error"]["Code"]
            time.sleep(3)
    assert manager_arn is not None, (
        f"could not create the configuration manager within the IAM role-propagation window "
        f"(last error: {last_create_error})"
    )
    ctx.on_cleanup(lambda: _delete_manager(qs, manager_arn))

    deny_role_name = ctx.unique_name("sim2real-qs-deny-")
    assume_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    deny_role_arn = iam.create_role(
        RoleName=deny_role_name,
        AssumeRolePolicyDocument=assume_trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=deny_role_name))

    deny_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
                # granted so the scoped-positive-control read below can distinguish "this one
                # action is denied" from "this principal has no ssm-quicksetup permissions at all"
                {"Effect": "Allow", "Action": "ssm-quicksetup:ListConfigurationManagers", "Resource": "*"},
                {"Effect": "Deny", "Action": "ssm-quicksetup:GetConfigurationManager", "Resource": "*"},
            ],
        }
    )
    iam.put_role_policy(RoleName=deny_role_name, PolicyName="deny-get-configuration-manager", PolicyDocument=deny_policy)
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=deny_role_name, PolicyName="deny-get-configuration-manager")
    )

    # the new role + inline deny policy may not be assumable/enforced instantly, so poll the
    # actual conditions (assumability, then the deny taking effect) to a bounded deadline
    # rather than sleeping a fixed duration up front.
    deadline = time.monotonic() + 60
    assumed = None
    last_assume_error = None
    while time.monotonic() < deadline:
        try:
            assumed = sts.assume_role(RoleArn=deny_role_arn, RoleSessionName="sim2real-behavioral-check")[
                "Credentials"
            ]
            break
        except ClientError as e:
            last_assume_error = e.response["Error"]["Code"]
            time.sleep(3)
    assert assumed is not None, (
        f"could not assume the deny-policy role within the eventual-consistency window "
        f"(last error: {last_assume_error})"
    )

    denied_client = ctx.client(
        "ssm-quicksetup",
        creds={
            "aws_access_key_id": assumed["AccessKeyId"],
            "aws_secret_access_key": assumed["SecretAccessKey"],
            "aws_session_token": assumed["SessionToken"],
        },
    )

    # the inline Deny may take a few seconds to be enforced, so a success here is the policy still
    # propagating; poll to a bounded deadline until the refusal appears.
    deadline = time.monotonic() + 60
    err = {}
    while time.monotonic() < deadline:
        try:
            denied_client.get_configuration_manager(ManagerArn=manager_arn)
            err = {}
        except ClientError as e:
            err = e.response["Error"]
            if err.get("Code") == "AccessDeniedException":
                break
        time.sleep(3)
    assert err.get("Code") == "AccessDeniedException", f"expected AccessDeniedException, got {err!r}"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{deny_role_name}/sim2real-behavioral-check "
        f"is not authorized to perform: ssm-quicksetup:GetConfigurationManager on resource: "
        f"{manager_arn} with an explicit deny in an identity-based policy"
    )
    assert err.get("Message") == expected_message, f"expected {expected_message!r}, got {err.get('Message')!r}"

    # scoped positive control: the SAME denied principal, granted only ListConfigurationManagers,
    # can still see this very manager through that other operation -- so the AccessDeniedException
    # above is the specific Deny statement being enforced, not a blanket lack of permissions or a
    # broken/unpropagated credential that would fail every ssm-quicksetup call identically. The
    # account is shared with concurrent runs that create their own managers, so page to exhaustion
    # (bounded) rather than trusting the manager onto a single unfiltered page.
    listed_arns = set()
    next_token = None
    for _ in range(200):
        kwargs = {"StartingToken": next_token} if next_token else {}
        page = denied_client.list_configuration_managers(**kwargs)
        listed_arns.update(m["ManagerArn"] for m in page["ConfigurationManagersList"])
        next_token = page.get("NextToken")
        if manager_arn in listed_arns or not next_token:
            break
    assert manager_arn in listed_arns, (
        f"the denied principal is only denied GetConfigurationManager, so ListConfigurationManagers "
        f"must eventually show {manager_arn} across pages; it did not appear"
    )

    # positive control: the original, fully-permissioned caller still reads it fine
    assert qs.get_configuration_manager(ManagerArn=manager_arn)["ManagerArn"] == manager_arn
    # deletion outlasts the teardown budget and needs the deployment roles teardown removes, so
    # the body deletes the manager itself; the registered teardown covers an early failure.
    _delete_manager(qs, manager_arn, timeout=240.0)


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
    lag), so retry MalformedPolicyDocument for a bounded window rather than failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_doc,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
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
        RoleName=admin_name,
        AssumeRolePolicyDocument=admin_trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
