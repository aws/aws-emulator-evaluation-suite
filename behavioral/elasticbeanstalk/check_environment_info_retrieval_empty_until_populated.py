"""environment-info-retrieval-empty-until-populated."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "environment-info-retrieval-empty-until-populated"
GROUP = "visibility-timeout-ttl"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RetrieveEnvironmentInfo returns no EnvironmentInfo items until the asynchronous
    RequestEnvironmentInfo tail-collection job finishes, then returns populated content."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    _create_running_environment(ctx, eb, app_name, env_name)

    # No one has ever requested info for this environment: must be empty.
    before = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")
    assert before["EnvironmentInfo"] == [], (
        f"expected no tail info before any RequestEnvironmentInfo call, got {before['EnvironmentInfo']}"
    )

    eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")

    info = _poll_until_populated(ctx, eb, env_name, timeout_s=300.0, interval_s=2.0)
    assert len(info) >= 1, f"RetrieveEnvironmentInfo never populated, got {info}"
    item = info[0]
    assert item["InfoType"] == "tail", f"expected InfoType 'tail', got {item.get('InfoType')!r}"
    assert item.get("Ec2InstanceId"), f"expected a non-empty Ec2InstanceId, got {item!r}"
    assert item.get("Message"), f"expected non-empty tail log content in Message, got {item!r}"


def _pick_solution_stack(ctx: Any, eb: Any) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux" in s and "running" in s and "Docker" not in s:
            return s
    return stacks[0]


def _wait_for_env_status(ctx: Any, eb: Any, env_name: str, target_statuses: set, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if envs:
            last = envs[0]["Status"]
            if last in target_statuses:
                return envs[0]
        time.sleep(2)
    raise AssertionError(f"environment {env_name} never reached {target_statuses}, last status={last}")


def _create_running_environment(ctx: Any, eb: Any, app_name: str, env_name: str) -> None:
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))
    stack = _pick_solution_stack(ctx, eb)
    _create_env_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": _ensure_instance_profile(ctx)},
        ],
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))
    _wait_for_env_status(ctx, eb, env_name, {"Ready"}, timeout_s=900.0)


def _ensure_instance_profile(ctx) -> str:
    """An EC2 instance profile carrying the EB web-tier policy: on an account with no default
    EB roles, CreateEnvironment stays in Launching without one."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-ec2-role-")
    profile_name = ctx.unique_name("sim2real-eb-ec2-profile-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name))
    deadline = time.monotonic() + 30.0
    while True:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(3.0)
    return profile_name


def _create_env_with_retry(ctx: Any, eb: Any, **kwargs: Any) -> dict:
    """CreateEnvironment, retried over the refusal Elastic Beanstalk returns while the IAM
    principals just created are not yet visible to it; anything else re-raises."""
    left = ctx.time_left()
    deadline = time.monotonic() + (120.0 if left is None else max(1.0, min(120.0, left - 5.0)))
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as exc:
            msg = exc.response["Error"].get("Message", "").lower()
            if time.monotonic() >= deadline or not (
                exc.response["Error"]["Code"] in ("InvalidParameterValue", "InsufficientPrivilegesException")
                and ("role" in msg or "instance profile" in msg or "permission" in msg)
            ):
                raise
            time.sleep(2)


def _terminate_env_and_wait(eb, env_name: str, timeout_s: float = 600.0) -> None:
    """Terminate the environment and wait until it is gone, so the instance profile it holds
    can be deleted; the call is re-issued while EB refuses it because the tail-log request is
    still pending deployment. An environment EB already removed counts as terminated."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eb.terminate_environment(EnvironmentName=env_name)
            break
        except ClientError as exc:
            if "not found" in str(exc).lower():
                return
            if "pending deployment" not in str(exc) or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if not envs or envs[0]["Status"] == "Terminated":
            return
        time.sleep(2.0)
    raise AssertionError(f"environment {env_name} not terminated within {timeout_s}s")


def _poll_until_populated(ctx: Any, eb: Any, env_name: str, timeout_s: float, interval_s: float) -> list:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")["EnvironmentInfo"]
        if info:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"RetrieveEnvironmentInfo never populated within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
