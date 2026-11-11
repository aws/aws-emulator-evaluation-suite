"""get-configuration-matches-created-definition."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-configuration-matches-created-definition"
GROUP = "state"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """A created manager's Configuration shows up in ListConfigurations by ManagerArn with the
    requested Type, Account, Region and ConfigurationDefinitionId, and GetConfiguration on its Id
    agrees and echoes the manager's TargetTagKey/TargetTagValue: both read paths see one config."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")
    account_id = _account_id(ctx)

    manager_arn = _create_manager_retrying_role_propagation(
        qs, ctx.unique_name("sim2real-qs-getconfig-"), ctx, admin_arn, exec_name, type_version
    )
    ctx.on_cleanup(lambda: _delete_manager_and_wait(qs, manager_arn))

    manager = qs.get_configuration_manager(ManagerArn=manager_arn)
    definition = manager["ConfigurationDefinitions"][0]
    definition_id = definition["Id"]

    configurations = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            resp = qs.list_configurations(ManagerArn=manager_arn)
        except ClientError as e:
            # ListConfigurations indexes managers behind GetConfigurationManager's own store,
            # so it can transiently ResourceNotFoundException on a manager moments old.
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(3)
            continue
        if resp["ConfigurationsList"]:
            configurations = resp["ConfigurationsList"]
            break
        time.sleep(3)
    assert configurations, "no Configuration materialized under ListConfigurations for this manager within 60s"

    config_summary = configurations[0]
    assert config_summary["ManagerArn"] == manager_arn, (
        f"expected ManagerArn {manager_arn!r}, got {config_summary['ManagerArn']!r}"
    )
    assert config_summary["Type"] == "AWSQuickSetupType-SSMHostMgmt", (
        f"expected Type 'AWSQuickSetupType-SSMHostMgmt', got {config_summary['Type']!r}"
    )
    assert config_summary["Account"] == account_id, (
        f"expected Account {account_id!r}, got {config_summary['Account']!r}"
    )
    assert config_summary["Region"] == ctx.region, (
        f"expected Region {ctx.region!r}, got {config_summary['Region']!r}"
    )
    assert config_summary["ConfigurationDefinitionId"] == definition_id, (
        f"expected ConfigurationDefinitionId {definition_id!r}, got {config_summary['ConfigurationDefinitionId']!r}"
    )

    got = None
    get_deadline = time.monotonic() + 60
    while time.monotonic() < get_deadline:
        try:
            got = qs.get_configuration(ConfigurationId=config_summary["Id"])
            break
        except ClientError as e:
            # GetConfiguration indexes behind ListConfigurations' own store, so it can
            # transiently ResourceNotFoundException on a configuration ListConfigurations
            # already shows.
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            time.sleep(3)
    assert got, f"GetConfiguration never found id {config_summary['Id']!r} within 60s of ListConfigurations returning it"
    # GetConfiguration's response has no Account/Region field at all (unlike the
    # ListConfigurations summary already checked above), so its agreement
    # with the created definition is checked on the fields it actually returns.
    assert got["ManagerArn"] == manager_arn, f"expected ManagerArn {manager_arn!r}, got {got['ManagerArn']!r}"
    assert got["Type"] == "AWSQuickSetupType-SSMHostMgmt", (
        f"expected Type 'AWSQuickSetupType-SSMHostMgmt', got {got['Type']!r}"
    )
    assert got["ConfigurationDefinitionId"] == definition_id, (
        f"expected ConfigurationDefinitionId {definition_id!r}, got {got['ConfigurationDefinitionId']!r}"
    )
    assert got["Parameters"]["TargetTagKey"] == definition["Parameters"]["TargetTagKey"], (
        f"expected TargetTagKey {definition['Parameters']['TargetTagKey']!r}, "
        f"got {got['Parameters']['TargetTagKey']!r}"
    )
    assert got["Parameters"]["TargetTagValue"] == definition["Parameters"]["TargetTagValue"], (
        f"expected TargetTagValue {definition['Parameters']['TargetTagValue']!r}, "
        f"got {got['Parameters']['TargetTagValue']!r}"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _delete_manager_and_wait(qs, manager_arn: str, timeout: float = 40.0) -> None:
    """DeleteConfigurationManager is asynchronous, and this check's own cleanup runs the
    admin/exec role teardown right after this callback (ctx.on_cleanup is LIFO, so this is the
    first cleanup to run, but the next ones fire within the same cleanup pass with no
    synchronization). If the manager's async deletion is still mid-flight when its dependency
    roles disappear, DeleteConfigurationManager can permanently AccessDeniedException on any
    later retry -- so wait for the manager to actually reach not-found before returning, bounded
    to leave the remaining cleanups their share of the shared cleanup budget."""
    _error_code(lambda: qs.delete_configuration_manager(ManagerArn=manager_arn))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            qs.get_configuration_manager(ManagerArn=manager_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)


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


def _create_manager_retrying_role_propagation(
    qs, name: str, ctx, admin_arn: str, exec_name: str, type_version: str, timeout: float = 180.0
) -> str:
    """CreateConfigurationManager has QuickSetup assume LocalDeploymentAdministrationRoleArn
    synchronously, so it can transiently AccessDeniedException while the roles created moments
    ago (and their attached policies) are still propagating through IAM -- retry that.

    It also enforces AWSQuickSetupType-SSMHostMgmt as a single-manager-per-account/region
    resource: a ConflictException names the ARN(s) of whatever manager already holds that
    type, regardless of how narrowly this manager's own TargetType/Tags scope the deployment.
    A manager left behind by an earlier run (crash before its own cleanup, or a cleanup whose
    role teardown outraced the manager's own async deletion) is adopted -- deleted, recreating
    its own dependency roles first if those are also gone -- and the create retried, rather than
    failing a re-run that finds the type slot occupied by dead state.
    """
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout
    last_code = None
    while time.monotonic() < deadline:
        try:
            return qs.create_configuration_manager(
                Name=name,
                ConfigurationDefinitions=[_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
            )["ManagerArn"]
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code == "AccessDeniedException":
                time.sleep(3)
                continue
            if last_code == "ConflictException":
                message = e.response["Error"].get("Message", "")
                for stale_arn in re.findall(r"arn:aws:ssm-quicksetup:[^\]\s,]+", message):
                    _adopt_stale_manager(qs, iam, stale_arn)
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"CreateConfigurationManager never succeeded, last error={last_code}")


def _adopt_stale_manager(qs, iam, stale_arn: str) -> None:
    """DeleteConfigurationManager re-assumes the stale manager's own
    LocalDeploymentAdministrationRoleArn to tear down what it deployed, and AccessDeniedExceptions
    permanently if that role (or the execution role it trusts) no longer exists. Recreate exactly
    the roles the stale manager's own definition names -- read from GetConfigurationManager, never
    guessed -- long enough for the delete to succeed, then remove whatever this helper recreated."""
    try:
        stale = qs.get_configuration_manager(ManagerArn=stale_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    # Only adopt a manager this suite created (Name and roles carry the suite prefix); any
    # other manager of this singleton type belongs to the account owner and is never touched.
    defs = stale.get("ConfigurationDefinitions") or [{}]
    defn = defs[0]
    admin_role_name = (defn.get("LocalDeploymentAdministrationRoleArn") or "").rsplit("/", 1)[-1]
    exec_role_name = defn.get("LocalDeploymentExecutionRoleName") or ""
    if not (
        (stale.get("Name") or "").startswith("sim2real-qs-")
        and admin_role_name.startswith("sim2real-qs-")
        and exec_role_name.startswith("sim2real-qs-")
    ):
        raise AssertionError(
            "precondition: the account already holds an AWSQuickSetupType-SSMHostMgmt manager this "
            f"suite did not create ({stale.get('Name') or stale_arn}); the type is an account/region "
            "singleton, so remove it or use another account/region"
        )
    recreated: list[str] = []

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
    admin_role_arn = _ensure_role_exists(iam, admin_role_name, admin_trust, recreated)
    exec_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_role_arn}, "Action": "sts:AssumeRole"}],
        }
    )
    _ensure_role_exists(iam, exec_role_name, exec_trust, recreated)

    deadline = time.monotonic() + 30.0
    delete_code = _error_code(lambda: qs.delete_configuration_manager(ManagerArn=stale_arn))
    while delete_code == "AccessDeniedException" and time.monotonic() < deadline:
        time.sleep(3)
        delete_code = _error_code(lambda: qs.delete_configuration_manager(ManagerArn=stale_arn))

    gone = False
    while time.monotonic() < deadline:
        try:
            qs.get_configuration_manager(ManagerArn=stale_arn)
        except ClientError as e:
            gone = e.response["Error"]["Code"] == "ResourceNotFoundException"
            break
        time.sleep(3)

    # Only tear down the roles this call recreated if the stale manager is actually gone --
    # otherwise a still-mid-flight async delete would lose its dependency roles exactly the way
    # the original leak did, and the next retry would have to recreate them again from scratch.
    if gone:
        for role_name in recreated:
            _error_code(
                lambda n=role_name: iam.detach_role_policy(
                    RoleName=n, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess"
                )
            )
            _error_code(lambda n=role_name: iam.delete_role(RoleName=n))


def _ensure_role_exists(iam, role_name: str, trust_doc: str, recreated: list) -> str:
    try:
        return iam.get_role(RoleName=role_name)["Role"]["Arn"]
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
    # the principal named in trust_doc (e.g. the just-recreated admin role) can suffer the same
    # IAM propagation lag _create_role_retrying_principal_lag exists to handle for the original
    # role creation, so retry MalformedPolicyDocument here too.
    _create_role_retrying_principal_lag(iam, role_name, trust_doc)
    arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    recreated.append(role_name)
    return arn


def _host_mgmt_definition(ctx, admin_arn: str, exec_name: str, type_version: str) -> dict:
    # AWSQuickSetupType-SSMHostMgmt is a single-manager-per-account/region resource: real AWS
    # ConflictExceptions CreateConfigurationManager against ANY existing manager of this type,
    # regardless of TargetType/Tags scope, not narrowed by scoping it to
    # a unique tag (see _create_manager_retrying_role_propagation's adopt-and-retry).
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
