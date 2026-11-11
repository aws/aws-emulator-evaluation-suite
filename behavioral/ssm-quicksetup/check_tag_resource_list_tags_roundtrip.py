"""tag-resource-list-tags-roundtrip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-list-tags-roundtrip"
GROUP = "tagging"
SERVICES = ["ssm-quicksetup"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """TagResource makes tags visible via ListTagsForResource, and once a manager is deleted
    ListTagsForResource on its ARN fails with ResourceNotFoundException while a second manager's
    tags remain readable: tags neither leak across resources nor outlive their owner."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")

    arn_a = qs.create_configuration_manager(
        Name=ctx.unique_name("sim2real-qs-tag-a-"),
        ConfigurationDefinitions=[_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
    )["ManagerArn"]
    ctx.on_cleanup(lambda: _delete_manager(qs, arn_a))

    arn_b = qs.create_configuration_manager(
        Name=ctx.unique_name("sim2real-qs-tag-b-"),
        ConfigurationDefinitions=[_distributor_definition(ctx, admin_arn, exec_name)],
    )["ManagerArn"]
    ctx.on_cleanup(lambda: _delete_manager(qs, arn_b))

    # TagResource rejects a manager still mid-deployment with ConflictException ("This
    # configuration manager is in DEPLOYING state and cannot be updated") -- confirmed on real
    # AWS, not guessed -- so wait for each manager's deployment to leave INITIALIZING/DEPLOYING
    # before tagging it.
    _wait_past_deploying(ctx, arn_a)
    _wait_past_deploying(ctx, arn_b)

    qs.tag_resource(ResourceArn=arn_a, Tags={"owner": "manager-a"})
    qs.tag_resource(ResourceArn=arn_b, Tags={"owner": "manager-b"})

    # The two shapes are NOT symmetric and botocore's own model says so: TagResource's `Tags` is a
    # `map`, ListTagsForResource's is a `list` of `{Key, Value}` structures. Comparing the returned
    # list straight against a dict could never hold.
    tags_a = _tags_as_dict(qs.list_tags_for_resource(ResourceArn=arn_a)["Tags"])
    assert tags_a == {"owner": "manager-a"}, f"expected manager A tags {{'owner': 'manager-a'}}, got {tags_a}"
    tags_b = _tags_as_dict(qs.list_tags_for_resource(ResourceArn=arn_b)["Tags"])
    assert tags_b == {"owner": "manager-b"}, f"expected manager B tags {{'owner': 'manager-b'}}, got {tags_b}"

    # break exactly one thing: remove manager A
    _delete_manager(qs, arn_a)

    deadline = time.monotonic() + 120
    code = None
    message = None
    while time.monotonic() < deadline:
        try:
            qs.get_configuration_manager(ManagerArn=arn_a)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message")
            if code == "ResourceNotFoundException":
                break
            raise
        time.sleep(3)
    assert code == "ResourceNotFoundException", "manager A was not actually removed"
    assert message == f"Quick setup manager with arn: {arn_a} could not be found.", message

    tag_err = _refusal(lambda: qs.list_tags_for_resource(ResourceArn=arn_a))
    assert tag_err["Code"] == "ResourceNotFoundException", (
        f"expected ListTagsForResource on deleted manager A to raise ResourceNotFoundException, got {tag_err['Code']}"
    )
    assert tag_err.get("Message") == "Configuration with requested id does not exist.", tag_err.get("Message")

    # a mutation on the dead id must also fail, not just a read
    tag_mutation_err = _refusal(lambda: qs.tag_resource(ResourceArn=arn_a, Tags={"owner": "post-delete"}))
    assert tag_mutation_err["Code"] == "ResourceNotFoundException", (
        f"expected TagResource on deleted manager A to raise ResourceNotFoundException, got {tag_mutation_err['Code']}"
    )
    assert tag_mutation_err.get("Message") == "Resource arn not found.", tag_mutation_err.get("Message")

    # positive control: manager B's tags are still intact and readable, unaffected by A's deletion
    tags_b_after = _tags_as_dict(qs.list_tags_for_resource(ResourceArn=arn_b)["Tags"])
    assert tags_b_after == {"owner": "manager-b"}, (
        f"expected manager B tags to remain {{'owner': 'manager-b'}} after A's deletion, got {tags_b_after}"
    )


# ===== helpers =====
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


def _tags_as_dict(tags) -> dict:
    """ListTagsForResource's `list` of `{Key, Value}` as the `map` TagResource accepts.

    Tolerates a map too, so the normalizer cannot itself become the thing that breaks if the
    response shape is ever widened.
    """
    if isinstance(tags, dict):
        return dict(tags)
    return {t["Key"]: t["Value"] for t in tags}





def _refusal(fn) -> dict:
    """The ClientError's Error dict of a call AWS refuses; a success fails the check."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError("call on the deleted manager succeeded; expected ResourceNotFoundException")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


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
    _wait_for_attached_policy(iam, admin_name, "arn:aws:iam::aws:policy/AdministratorAccess")
    _wait_for_attached_policy(iam, exec_name, "arn:aws:iam::aws:policy/AdministratorAccess")
    return admin_arn, exec_name


def _wait_for_attached_policy(iam, role_name: str, policy_arn: str, timeout: float = 30.0) -> None:
    """IAM policy attachment is eventually consistent -- Quick Setup can attempt to assume the
    role before the attachment is visible everywhere, so poll for it instead of guessing a delay."""
    deadline = time.monotonic() + timeout
    while True:
        attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
        if any(p["PolicyArn"] == policy_arn for p in attached):
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"{policy_arn} never became visible on role {role_name}'s attached-policy list")
        time.sleep(3)


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


def _latest_type_version(ctx, type_name: str) -> str:
    qs = ctx.client("ssm-quicksetup")
    for t in qs.list_quick_setup_types()["QuickSetupTypeList"]:
        if t["Type"] == type_name:
            return t["LatestVersion"]
    raise AssertionError(f"quick setup type {type_name} not found in ListQuickSetupTypes")


def _host_mgmt_definition(ctx, admin_arn: str, exec_name: str, type_version: str) -> dict:
    # Confirmed on real AWS: a Quick Setup configuration-manager TYPE is an account/region
    # singleton -- a second manager of the SAME type conflicts regardless of target scoping
    # (Tags vs "*"), and this holds for Distributor too, not just SSMHostMgmt. Manager A and
    # manager B must therefore use two DIFFERENT types; SSMHostMgmt is manager A's.
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
    # Manager B's type: Distributor, so it doesn't collide with manager A's SSMHostMgmt
    # singleton (see _host_mgmt_definition).
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
