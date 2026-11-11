"""concurrent-apply-same-managed-action-id-race."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-apply-same-managed-action-id-race"
GROUP = "concurrency"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent applies of one managed action id: exactly one succeeds, the other gets
    ManagedActionInvalidStateException, and history records exactly one execution."""
    eb = ctx.client("elasticbeanstalk")
    iam = ctx.client("iam")
    app_name = ctx.unique_name("sim2real-ebrace-app-")
    env_name = _short_env_name(ctx, "ebrace")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    # The API cannot force a platform-update action to be scheduled, so the environment launches
    # on an older version of a branch that has a newer Ready version.
    platform_arn = _pick_old_platform_arn(eb)
    if platform_arn is None:
        raise AssertionError(
            "no platform branch in this account/region currently has two or more Ready versions, "
            "so there is no way to guarantee a platform update is available to schedule; retry "
            "once such a branch exists"
        )
    ec2_profile, service_role = _create_eb_roles(ctx, iam)

    _create_environment_with_retry(
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        PlatformArn=platform_arn,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
            {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:00:00"},
            {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": service_role},
        ],
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))
    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env["Status"] == "Ready", f"environment entered {env['Status']} instead of Ready"

    pending = _poll_until(
        lambda: eb.describe_environment_managed_actions(EnvironmentName=env_name, Status="Scheduled").get(
            "ManagedActions", []
        ),
        lambda actions: len(actions) > 0,
        timeout_s=1800.0,
        interval_s=30.0,
    )
    if not pending:
        raise AssertionError(
            "AWS never scheduled a managed action for this environment within the poll window; "
            "cannot exercise the apply-race without a real pending action"
        )
    action_id = pending[0]["ActionId"]

    def _apply():
        try:
            eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action_id)
            return ("ok", None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _apply(), range(2)))

    outcomes = [r[0] for r in results]
    codes = [r[1] for r in results if r[0] == "error"]

    successes = outcomes.count("ok")
    assert successes == 1, f"expected exactly one racer to succeed applying {action_id}, got outcomes={results}"
    assert len(codes) == 1, f"expected exactly one racer to fail, got outcomes={results}"
    assert codes[0] == "ManagedActionInvalidStateException", (
        f"expected the losing racer to get ManagedActionInvalidStateException, got {codes[0]!r}"
    )

    history = _poll_until(
        lambda: [
            h
            for h in eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
                "ManagedActionHistoryItems", []
            )
            if h["ActionId"] == action_id
        ],
        lambda items: len(items) >= 1,
        timeout_s=900.0,
        interval_s=30.0,
    )
    assert len(history) == 1, (
        f"expected exactly one managed-action history entry for {action_id}, got {len(history)}: {history}"
    )


def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


def _version_key(v: dict) -> tuple:
    raw = v.get("PlatformVersion", "")
    parts = []
    for p in raw.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(-1)
    return tuple(parts)


def _pick_old_platform_arn(eb) -> str | None:
    """Return the oldest version of a supported branch that has a newer Ready version, or None.

    The launch version need not be Ready: AWS updates Deprecated environments too."""
    branches = []
    token = None
    while True:
        kwargs = {
            "Filters": [{"Attribute": "LifecycleState", "Operator": "=", "Values": ["supported"]}],
            "MaxRecords": 100,
        }
        if token:
            kwargs["NextToken"] = token
        resp = eb.list_platform_branches(**kwargs)
        branches.extend(resp.get("PlatformBranchSummaryList", []))
        token = resp.get("NextToken")
        if not token:
            break

    for branch in branches:
        name = branch.get("BranchName")
        if not name:
            continue
        versions = []
        vtoken = None
        while True:
            vkwargs = {"Filters": [{"Type": "PlatformBranchName", "Operator": "=", "Values": [name]}]}
            if vtoken:
                vkwargs["NextToken"] = vtoken
            vresp = eb.list_platform_versions(**vkwargs)
            versions.extend(vresp.get("PlatformSummaryList", []))
            vtoken = vresp.get("NextToken")
            if not vtoken:
                break
        ready = [v for v in versions if v.get("PlatformStatus") == "Ready"]
        if not ready:
            continue
        newest_ready = max(ready, key=_version_key)
        older = [v for v in versions if _version_key(v) < _version_key(newest_ready)]
        if older:
            oldest = min(older, key=_version_key)
            return oldest["PlatformArn"]
    return None


def _create_eb_roles(ctx, iam) -> tuple[str, str]:
    suffix = ctx.unique_name("sim2real-ebrole-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"
    tag = [{"Key": "sim2real", "Value": "true"}]

    svc_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust, Tags=tag)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust, Tags=tag)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    )

    iam.create_instance_profile(InstanceProfileName=ec2_name, Tags=tag)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    return ec2_name, svc_name


def _create_environment_with_retry(eb, **kwargs):
    # IAM eventual consistency: a just-created role or instance profile is rejected with
    # InsufficientPrivilegesException until it propagates.
    last_err = None
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] == "InsufficientPrivilegesException":
                last_err = err
                time.sleep(2)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    return value


def _wait_env_status(ctx, env_name: str, targets, timeout_s: float = 1200.0, interval_s: float = 20.0):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        envs = resp.get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
