"""e2e-operations-role-gates-managed-action-apply."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-operations-role-gates-managed-action-apply"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx: Any) -> None:
    """With an operations role associated, an applied PlatformUpdate managed action completes and changes the
    environment's PlatformArn; disassociating the role then clears OperationsRole."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb1-app-")
    env_name = ctx.unique_name("sim2real-eb1-env-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    ops_role_arn = _create_operations_role(ctx)
    svc_role_name, ec2_profile_name = _create_eb_roles(ctx, ctx.client("iam"))
    old_platform_arn = _pick_old_platform_arn(ctx)

    _create_environment_with_retry(
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        PlatformArn=old_platform_arn,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:00:00"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
        ],
    )
    ctx.on_cleanup(lambda: _terminate_env(ctx, eb, env_name))

    ready = _wait_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0)
    initial_platform_arn = ready["PlatformArn"]

    eb.associate_environment_operations_role(EnvironmentName=env_name, OperationsRole=ops_role_arn)
    associated = _wait_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0],
        lambda e: e.get("OperationsRole") == ops_role_arn,
        timeout_s=120.0,
    )
    assert associated["OperationsRole"] == ops_role_arn, (
        f"expected OperationsRole={ops_role_arn!r} after associate, "
        f"got {associated.get('OperationsRole')!r}"
    )

    scheduled = _wait_scheduled_platform_update(ctx, env_name, timeout_s=1800.0)
    if scheduled is None:
        raise AssertionError(
            "AWS never scheduled a PlatformUpdate managed action for this environment "
            "within the 30-minute poll window; the update-detection cadence for managed "
            "platform updates is an AWS-internal background process we cannot force "
            "deterministically, even though we created the environment on an older "
            "platform version specifically to make an update available."
        )

    apply_resp = eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=scheduled["ActionId"])
    assert apply_resp["Status"] in ("Running", "Pending", "Scheduled"), (
        f"expected ApplyEnvironmentManagedAction to report an in-flight status, "
        f"got {apply_resp.get('Status')!r}"
    )

    history_item = _wait_until(
        lambda: _find_history_item(eb, env_name, scheduled["ActionId"]),
        lambda item: item is not None and item.get("Status") in ("Completed", "Failed", "Unknown"),
        timeout_s=1200.0,
        interval_s=20.0,
    )
    assert history_item is not None, (
        f"managed action {scheduled['ActionId']} never appeared in managed-action history"
    )
    assert history_item["Status"] == "Completed", (
        f"expected managed action {scheduled['ActionId']} history status Completed, "
        f"got {history_item.get('Status')!r}"
    )

    updated = _wait_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0],
        lambda e: e.get("PlatformArn") != initial_platform_arn,
        timeout_s=300.0,
    )
    assert updated["PlatformArn"] != initial_platform_arn, (
        f"expected PlatformArn to change from {initial_platform_arn!r} after the applied "
        f"managed action completed, but it did not"
    )

    eb.disassociate_environment_operations_role(EnvironmentName=env_name)
    disassociated = _wait_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0],
        lambda e: not e.get("OperationsRole"),
        timeout_s=120.0,
    )
    assert not disassociated.get("OperationsRole"), (
        f"expected OperationsRole to be cleared after disassociate, "
        f"got {disassociated.get('OperationsRole')!r}"
    )

    eb.terminate_environment(EnvironmentName=env_name)
    _wait_env_status(ctx, env_name, {"Terminated"}, timeout_s=600.0)


def _wait_until(probe, predicate, timeout_s: float, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s; last observed={last!r}")


def _wait_env_status(ctx, env_name: str, target_statuses: set, timeout_s: float):
    eb = ctx.client("elasticbeanstalk")
    return _wait_until(
        lambda: eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"][0],
        lambda e: e.get("Status") in target_statuses,
        timeout_s=timeout_s,
        interval_s=15.0,
    )


def _create_operations_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb1-ops-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role_arn


def _create_eb_roles(ctx, iam) -> tuple[str, str]:
    """A custom service role + EC2 instance profile, required because the default
    service-linked role forbids ManagedActionsEnabled."""
    suffix = ctx.unique_name("sim2real-eb1-role-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

    svc_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    ec2_trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    web_tier = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn=web_tier)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn=web_tier))

    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    return svc_name, ec2_name


def _create_environment_with_retry(eb, **kwargs):
    """CreateEnvironment, retried every 2 s while Elastic Beanstalk cannot yet pass the roles
    just created (IAM propagation); any other refusal raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90.0
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _terminate_env(ctx, eb, env_name) -> None:
    """TerminateEnvironment, retried every 2 s while the environment is mid-operation ("invalid
    state"), then waited to Terminated so its roles outlive it; a not-found message means gone."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600
    while True:
        try:
            eb.terminate_environment(EnvironmentName=env_name)
            break
        except ClientError as exc:
            code, msg = exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
            if code == "InvalidParameterValue" and (
                    "No Environment found" in msg or "Environment not found with Name" in msg):
                return
            if code != "InvalidParameterValue" or "invalid state" not in msg or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_env_status(ctx, env_name, {"Terminated"}, timeout_s=max(1.0, deadline - time.monotonic()))


def _pick_old_platform_arn(ctx) -> str:
    """Find a Ready platform version that is NOT the newest in its branch."""
    eb = ctx.client("elasticbeanstalk")
    by_branch: dict[str, list[dict]] = {}
    next_token = None
    for _ in range(4):
        kwargs = {"Filters": [{"Type": "PlatformStatus", "Operator": "=", "Values": ["Ready"]}], "MaxRecords": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = eb.list_platform_versions(**kwargs)
        for p in resp.get("PlatformSummaryList", []):
            branch = p.get("PlatformBranchName")
            version = p.get("PlatformVersion")
            if not branch or not version:
                continue
            parts = version.split(".")
            if not all(part.isdigit() for part in parts):
                continue
            by_branch.setdefault(branch, []).append(p)
        next_token = resp.get("NextToken")
        if not next_token:
            break
    for versions in by_branch.values():
        if len(versions) < 2:
            continue
        versions.sort(key=lambda p: tuple(int(x) for x in p["PlatformVersion"].split(".")), reverse=True)
        return versions[-1]["PlatformArn"]
    raise AssertionError(
        "no Elastic Beanstalk platform branch has 2+ Ready versions in this account/region "
        "right now to construct a genuine 'not the newest' update opportunity -- every branch's "
        "ListPlatformVersions entry today shows exactly one (Recommended) version; would need to "
        "retry once AWS publishes a second version for at least one branch"
    )


def _find_history_item(eb, env_name: str, action_id: str):
    resp = eb.describe_environment_managed_action_history(EnvironmentName=env_name)
    for item in resp.get("ManagedActionHistoryItems", []):
        if item.get("ActionId") == action_id:
            return item
    return None


def _wait_scheduled_platform_update(ctx, env_name: str, timeout_s: float):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled")
        for action in resp.get("ManagedActions", []):
            if action.get("ActionType") == "PlatformUpdate":
                return action
        time.sleep(2.0)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
