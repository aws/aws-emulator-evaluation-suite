"""list-configuration-managers-pagination-max-items."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-configuration-managers-pagination-max-items"
GROUP = "lifecycle"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """ListConfigurationManagers with MaxItems=1 returns at most one manager per page, and following
    NextToken to exhaustion returns each created manager exactly once; the two managers are of two
    types because each Quick Setup type is an account/region singleton."""
    qs = ctx.client("ssm-quicksetup")
    iam = ctx.client("iam")
    _clear_stale_distributor_managers(qs, iam)

    admin_arn, exec_name = _create_local_roles(ctx)
    host_mgmt_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")

    definitions = [
        ("sim2real-qs-page-hostmgmt-", _host_mgmt_definition(ctx, admin_arn, exec_name, host_mgmt_version)),
        ("sim2real-qs-page-distributor-", _distributor_definition(ctx, admin_arn, exec_name)),
    ]
    created_arns = []
    for name_prefix, definition in definitions:
        name = ctx.unique_name(name_prefix)
        arn = _create_manager_with_retry(qs, name, definition)
        created_arns.append(arn)
        ctx.on_cleanup(lambda a=arn: _delete_manager_and_wait(qs, a, timeout=240.0))

    seen = {}
    token = None
    for _ in range(50):
        kwargs = {"MaxItems": 1}
        if token:
            kwargs["StartingToken"] = token
        page = qs.list_configuration_managers(**kwargs)
        assert len(page["ConfigurationManagersList"]) <= 1, "MaxItems=1 page returned more than one item"
        for m in page["ConfigurationManagersList"]:
            seen[m["ManagerArn"]] = seen.get(m["ManagerArn"], 0) + 1
        token = page.get("NextToken")
        if not token:
            break

    for arn in created_arns:
        assert seen.get(arn) == 1, f"manager {arn} was not returned exactly once across paginated pages"

    # deletion needs the deployment roles teardown removes, so the body deletes the managers
    # itself; the registered teardown covers an early failure.
    for arn in created_arns:
        _delete_manager_and_wait(qs, arn, timeout=240.0)


def _best_effort(fn):
    """Adopt-or-create and stale-manager setup only: a refusal here never grades the check."""
    try:
        fn()
    except ClientError:
        pass


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_manager_with_retry(qs, name: str, definition: dict, timeout: float = 60.0) -> str:
    """A fresh configuration manager create can transiently fail -- the local deployment roles
    it references may not yet be visible (IAM propagation lag), or a residual manager of the
    same type may still be tearing down -- so retry the actual create call for a bounded window
    instead of guessing a fixed delay up front."""
    deadline = time.monotonic() + timeout
    last_error = None
    while True:
        try:
            return qs.create_configuration_manager(
                Name=name, ConfigurationDefinitions=[definition], Tags={"sim2real-check": CHECK}
            )["ManagerArn"]
        except ClientError as e:
            last_error = e.response["Error"]["Code"]
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"create_configuration_manager for {name} still failing after {timeout}s of retries "
                    f"(last error: {last_error})"
                ) from e
            time.sleep(3)


def _latest_type_version(ctx, type_name: str) -> str:
    qs = ctx.client("ssm-quicksetup")
    for t in qs.list_quick_setup_types()["QuickSetupTypeList"]:
        if t["Type"] == type_name:
            return t["LatestVersion"]
    raise AssertionError(f"quick setup type {type_name} not found in ListQuickSetupTypes")


def _admin_trust_doc() -> str:
    return json.dumps(
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


def _exec_trust_doc(admin_arn: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}],
        }
    )


def _create_role_retrying_principal_lag(iam, role_name: str, trust_doc: str, timeout: float = 30.0) -> None:
    """iam.create_role validates that AWS principals named in the trust policy already exist.
    A role created moments ago may not yet be visible to that validation check (IAM propagation
    lag), so retry MalformedPolicyDocument for a bounded window instead of failing outright."""
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


def _adopt_role(iam, role_name: str, trust_doc: str, timeout: float = 60.0) -> bool:
    """Create-or-adopt: the role may already exist (the common case) or may need recreating
    because a run's cleanup deleted it (see _clear_stale_distributor_managers). Returns True
    only when this call created the role."""
    created = False
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=trust_doc,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            created = True
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "EntityAlreadyExists" or time.monotonic() > deadline:
                break
        time.sleep(3)
    _best_effort(lambda: iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"))
    return created


def _create_local_roles(ctx):
    iam = ctx.client("iam")
    admin_name = ctx.unique_name("sim2real-qs-admin-")
    exec_name = ctx.unique_name("sim2real-qs-exec-")

    admin_arn = iam.create_role(
        RoleName=admin_name,
        AssumeRolePolicyDocument=_admin_trust_doc(),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=admin_name))
    iam.attach_role_policy(RoleName=admin_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=admin_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    )

    # the execution role must trust the ADMINISTRATION role (self-managed StackSets model),
    # not a service principal -- Quick Setup's admin role assumes it to deploy resources.
    # IAM Principal existence checks on the trust policy can lag the admin role's own creation
    # (eventual consistency), so retry MalformedPolicyDocument for a bounded window.
    _create_role_retrying_principal_lag(iam, exec_name, _exec_trust_doc(admin_arn))
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


def _distributor_definition(ctx, admin_arn: str, exec_name: str) -> dict:
    # AWSQuickSetupType-Distributor is used here as a second, independent type -- like
    # AWSQuickSetupType-SSMHostMgmt, it is an account/region singleton per type
    # (ConflictException "Found existing resources for type" otherwise, regardless of
    # TargetTagKey/TargetTagValue scoping); see _clear_stale_distributor_managers above.
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


def _list_all_configuration_managers(qs) -> list:
    managers = []
    token = None
    while True:
        kwargs = {"MaxItems": 100}
        if token:
            kwargs["StartingToken"] = token
        page = qs.list_configuration_managers(**kwargs)
        managers.extend(page["ConfigurationManagersList"])
        token = page.get("NextToken")
        if not token:
            return managers


def _deployment_status(qs, manager_arn: str):
    manager = qs.get_configuration_manager(ManagerArn=manager_arn)
    summaries = manager.get("StatusSummaries", [])
    entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
    return (entry["Status"] if entry else None), manager


def _wait_gone(qs, manager_arn: str, deadline: float) -> bool:
    while time.monotonic() < deadline:
        try:
            qs.get_configuration_manager(ManagerArn=manager_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return True
            raise
        time.sleep(5)
    return False


def _delete_manager_and_wait(qs, manager_arn: str, timeout: float) -> None:
    """Delete the manager and wait until it is gone. A ConflictException (deployment still
    running) is retried; a manager left behind blocks every later manager of its type in the
    account, so a timeout or any other refusal raises."""
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
    if not _wait_gone(qs, manager_arn, deadline):
        raise AssertionError(f"configuration manager {manager_arn} was not deleted within {timeout}s")


_SUITE_PREFIX = "sim2real-qs-"


def _clear_stale_distributor_managers(qs, iam, timeout: float = 240.0) -> None:
    """Clear Distributor managers this suite left behind (Name starts with _SUITE_PREFIX). Any
    other Distributor manager is not ours: fail with a precondition error instead of deleting it."""
    deadline = time.monotonic() + timeout
    while True:
        distributor = [
            m
            for m in _list_all_configuration_managers(qs)
            if any(
                d.get("Type") == "AWSQuickSetupType-Distributor"
                for d in m.get("ConfigurationDefinitionSummaries", [])
            )
        ]
        foreign = [
            m.get("Name") or m["ManagerArn"]
            for m in distributor
            if not (m.get("Name") or "").startswith(_SUITE_PREFIX)
        ]
        if foreign:
            raise AssertionError(
                "precondition: the account already holds an AWSQuickSetupType-Distributor manager "
                f"this suite did not create ({foreign}); the type is an account/region singleton, "
                "so remove it or use another account/region"
            )
        stale = [m["ManagerArn"] for m in distributor]
        if not stale:
            return
        assert time.monotonic() < deadline, f"stale AWSQuickSetupType-Distributor manager(s) never cleared: {stale}"
        for arn in stale:
            if time.monotonic() > deadline:
                break
            status, manager = _deployment_status(qs, arn)
            if status in ("INITIALIZING", "DEPLOYING"):
                continue

            # DeleteConfigurationManager's own async teardown needs the deployment's local
            # roles to still exist -- if the roles it names no longer exist, the delete is
            # accepted but the manager is not removed until those roles exist again. Re-adopt
            # those exact roles (suite-named ones only) from the stale manager's own definition
            # before retrying delete, and remember which ones this helper recreated.
            recreated: list[str] = []
            for defn in manager.get("ConfigurationDefinitions", []):
                stale_admin_arn = defn.get("LocalDeploymentAdministrationRoleArn")
                stale_exec_name = defn.get("LocalDeploymentExecutionRoleName")
                stale_admin_name = stale_admin_arn.rsplit("/", 1)[-1] if stale_admin_arn else ""
                if stale_admin_name.startswith(_SUITE_PREFIX):
                    if _adopt_role(iam, stale_admin_name, _admin_trust_doc()):
                        recreated.append(stale_admin_name)
                if stale_exec_name and stale_exec_name.startswith(_SUITE_PREFIX) and stale_admin_arn:
                    if _adopt_role(iam, stale_exec_name, _exec_trust_doc(stale_admin_arn)):
                        recreated.append(stale_exec_name)

            _best_effort(lambda arn=arn: qs.delete_configuration_manager(ManagerArn=arn))
            gone = _wait_gone(qs, arn, deadline)

            # only remove the roles this helper recreated, and only once the manager is gone.
            if gone:
                for role_name in reversed(recreated):
                    _best_effort(
                        lambda n=role_name: iam.detach_role_policy(
                            RoleName=n, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
                        )
                    )
                    _best_effort(lambda n=role_name: iam.delete_role(RoleName=n))
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
