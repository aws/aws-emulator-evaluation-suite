"""untag-resource-empty-tag-keys-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-empty-tag-keys-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-quicksetup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-quicksetup-configuration-manager")
def run(ctx) -> None:
    """UntagResource with an empty TagKeys list (no tagKeys query parameter on the wire) fails with
    UnauthorizedException "Unauthorized" and leaves the tag in place, while untagging the real key removes it."""
    qs = ctx.client("ssm-quicksetup")
    admin_arn, exec_name = _create_local_roles(ctx)
    type_version = _latest_type_version(ctx, "AWSQuickSetupType-SSMHostMgmt")
    _clear_existing_host_mgmt_managers(ctx, qs)

    manager_arn = _create_configuration_manager_retrying_role_propagation(
        qs,
        Name=ctx.unique_name("sim2real-qs-untagempty-"),
        ConfigurationDefinitions=[_host_mgmt_definition(ctx, admin_arn, exec_name, type_version)],
        Tags={"keep": "me"},
    )["ManagerArn"]
    ctx.on_cleanup(lambda: _delete_manager(qs, manager_arn))

    # a manager under active deployment refuses tag mutations (ConflictException)
    # -- wait past the transient INITIALIZING/DEPLOYING window first.
    _wait_past_deploying(qs, manager_arn)

    err = _client_error(lambda: qs.untag_resource(ResourceArn=manager_arn, TagKeys=[]))
    code = err.get("Code")
    assert code == "UnauthorizedException", f"expected UnauthorizedException, got {code!r} ({err!r})"
    assert err.get("Message") == "Unauthorized", f"expected message 'Unauthorized', got {err.get('Message')!r}"

    # effect absent: the tag survives the rejected call
    tags_after_reject = _tags_map(qs, manager_arn)
    assert tags_after_reject == {"keep": "me"}, (
        f"expected the tag to survive the rejected UntagResource, got {tags_after_reject!r}"
    )

    # positive control: untagging with a real key succeeds
    qs.untag_resource(ResourceArn=manager_arn, TagKeys=["keep"])
    tags_after_untag = _tags_map(qs, manager_arn)
    assert tags_after_untag == {}, f"expected UntagResource to remove the key, got {tags_after_untag!r}"
    # deletion outlasts the teardown budget and needs the deployment roles teardown removes, so
    # the body deletes the manager itself; the registered teardown covers an early failure.
    _delete_manager(qs, manager_arn, timeout=240.0)


def _wait_past_deploying(qs, manager_arn: str, timeout: float = 180.0) -> str:
    """A manager still in INITIALIZING/DEPLOYING refuses tag mutations with ConflictException
   , so wait for the async deployment orchestration to move past
    those transient statuses before touching tags."""
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        summaries = qs.get_configuration_manager(ManagerArn=manager_arn).get("StatusSummaries", [])
        entry = next((s for s in summaries if s["StatusType"] == "Deployment"), None)
        status = entry["Status"] if entry else None
        if status not in (None, "INITIALIZING", "DEPLOYING"):
            return status
        time.sleep(5)
    raise AssertionError(f"deployment still {status!r} {timeout}s after creation")


def _tags_map(qs, resource_arn: str) -> dict:
    """ListTagsForResource returns Tags as a LIST of {Key, Value} entries,
    not the TagsMap dict that CreateConfigurationManager/TagResource take as input --
    normalize to a dict for comparison."""
    return {t["Key"]: t["Value"] for t in qs.list_tags_for_resource(ResourceArn=resource_arn)["Tags"]}


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
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


_SUITE_PREFIX = "sim2real-qs-"
_MISSING_ROLE_RE = re.compile(r"Role (\S+) can't be accessed")
_STALE_EXEC_TRUST_RE = re.compile(r"trust policy does not allow AssumeRole for (arn:aws:iam::\d+:role/\S+)")


def _clear_existing_host_mgmt_managers(ctx, qs, timeout: float = 90.0) -> None:
    """AWSQuickSetupType-SSMHostMgmt is an account-wide singleton REGARDLESS of target scoping
    (a manager scoped to an unrelated tag still ConflictExceptions a
    second SSMHostMgmt manager -- tag-scoping only isolates the deployment's blast radius, not
    the type-level singleton). Clear only managers of this type that this suite left behind (Name
    starts with _SUITE_PREFIX), e.g. one left by an interrupted prior run whose own local role it
    may have outlived -- deletion then needs that role to exist again just long enough to tear
    down. Any other manager of this type is not ours: fail with a precondition error instead."""
    stale_arns = []
    foreign = []
    kwargs: dict = {}
    while True:
        page = qs.list_configuration_managers(**kwargs)
        for summary in page.get("ConfigurationManagersList", []):
            defs = summary.get("ConfigurationDefinitionSummaries", [])
            if any(d.get("Type") == "AWSQuickSetupType-SSMHostMgmt" for d in defs):
                if (summary.get("Name") or "").startswith(_SUITE_PREFIX):
                    stale_arns.append(summary["ManagerArn"])
                else:
                    foreign.append(summary.get("Name") or summary["ManagerArn"])
        token = page.get("NextToken")
        if not token:
            break
        kwargs["StartingToken"] = token
    if foreign:
        raise AssertionError(
            "precondition: the account already holds an AWSQuickSetupType-SSMHostMgmt manager this "
            f"suite did not create ({foreign}); the type is an account/region singleton, so remove it "
            "or use another account/region"
        )

    iam = ctx.client("iam")
    for arn in stale_arns:
        recreated_roles: list[str] = []
        fixed_exec_trust = False
        deadline = time.monotonic() + timeout
        while True:
            try:
                qs.delete_configuration_manager(ManagerArn=arn)
                break
            except ClientError as e:
                code = e.response["Error"]["Code"]
                message = e.response["Error"].get("Message", "")
                if code == "ResourceNotFoundException":
                    break
                missing_role = _MISSING_ROLE_RE.search(message)
                stale_trust = _STALE_EXEC_TRUST_RE.search(message)
                # only suite-named roles are ever recreated or modified here.
                if code == "AccessDeniedException" and missing_role and missing_role.group(1).startswith(_SUITE_PREFIX):
                    role_name = missing_role.group(1)
                    if role_name not in recreated_roles and _ensure_throwaway_role(iam, role_name):
                        recreated_roles.append(role_name)
                        continue
                if code == "ValidationException" and stale_trust and not fixed_exec_trust:
                    # the admin role may have just been recreated under the same name, which IAM
                    # gives a fresh internal unique ID -- the exec role's stored trust still
                    # pins the OLD one, so its AssumeRole of the "same" admin ARN fails. The
                    # admin role named in THIS message may itself be missing too (a prior run's
                    # cleanup can delete both roles while the async manager delete is still
                    # pending) -- ensure it exists before repointing exec's trust at it.
                    admin_arn = stale_trust.group(1)
                    admin_role_name = admin_arn.rsplit("/", 1)[-1]
                    exec_name = qs.get_configuration_manager(ManagerArn=arn)["ConfigurationDefinitions"][0][
                        "LocalDeploymentExecutionRoleName"
                    ]
                    if admin_role_name.startswith(_SUITE_PREFIX) and exec_name.startswith(_SUITE_PREFIX):
                        if admin_role_name not in recreated_roles and _ensure_throwaway_role(iam, admin_role_name):
                            recreated_roles.append(admin_role_name)
                        _repoint_exec_role_trust(iam, exec_name, admin_arn)
                        fixed_exec_trust = True
                        continue
                if code != "ConflictException" or time.monotonic() > deadline:
                    raise
                time.sleep(5)

        # DeleteConfigurationManager returns before the delete is actually visible elsewhere
        # (an immediate CreateConfigurationManager retry can still see
        # this exact ManagerArn as an existing resource) -- poll for the independent read to
        # agree before treating it as gone.
        gone_deadline = time.monotonic() + timeout
        while time.monotonic() < gone_deadline:
            try:
                qs.get_configuration_manager(ManagerArn=arn)
            except ClientError as e:
                if e.response["Error"]["Code"] == "ResourceNotFoundException":
                    break
                raise
            time.sleep(5)
        else:
            raise AssertionError(f"{arn} still visible via GetConfigurationManager {timeout}s after delete")

        for role_name in recreated_roles:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
            iam.delete_role(RoleName=role_name)


def _repoint_exec_role_trust(iam, exec_role_name: str, admin_arn: str, timeout: float = 30.0) -> None:
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": admin_arn}, "Action": "sts:AssumeRole"}],
        }
    )
    # same IAM principal-existence propagation lag _create_role_retrying_principal_lag guards
    # against, just hit through UpdateAssumeRolePolicy rather than CreateRole -- admin_arn may
    # have been (re)created moments ago and not yet visible to this validation check.
    deadline = time.monotonic() + timeout
    while True:
        try:
            iam.update_assume_role_policy(RoleName=exec_role_name, PolicyDocument=trust)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _ensure_throwaway_role(iam, role_name: str) -> bool:
    """Create role_name (with the trust/permissions Quick Setup deployment roles need) if it
    doesn't currently exist. Returns True if it created the role (caller owns tearing it down),
    False if the role was already there (someone else's, not ours to delete)."""
    try:
        iam.get_role(RoleName=role_name)
        return False
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise
    _recreate_throwaway_teardown_role(iam, role_name)
    return True


def _recreate_throwaway_teardown_role(iam, role_name: str) -> None:
    trust = json.dumps(
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")


def _create_configuration_manager_retrying_role_propagation(qs, timeout: float = 30.0, **kwargs):
    """The roles just created may not yet be visible to Quick Setup's own role validation (IAM
    eventual consistency), so retry AccessDeniedException/ValidationException for a bounded
    window rather than failing outright."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            return qs.create_configuration_manager(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException") or (
                time.monotonic() > deadline
            ):
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


def _host_mgmt_definition(ctx, admin_arn: str, exec_name: str, type_version: str) -> dict:
    # AWSQuickSetupType-SSMHostMgmt is an account-wide singleton by TYPE, not just when
    # TargetType="*": a second manager of this type ConflictExceptions even when scoped to an
    # unrelated tag (_clear_existing_host_mgmt_managers handles this). The unique tag here only
    # keeps the deployment itself from matching any real instance.
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
