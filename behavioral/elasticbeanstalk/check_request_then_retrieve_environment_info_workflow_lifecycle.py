"""request-then-retrieve-environment-info-workflow-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "request-then-retrieve-environment-info-workflow-lifecycle"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestEnvironmentInfo creates a pending info job that RetrieveEnvironmentInfo can
    subsequently fetch once populated."""
    eb = ctx.client("elasticbeanstalk")
    env = _create_ready_environment(ctx)
    env_name = env["env_name"]


    baseline = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")["EnvironmentInfo"]
    assert baseline == [], f"expected no tail info before any RequestEnvironmentInfo call, got {baseline}"

    eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")

    info = _poll_environment_info(ctx, env_name, timeout_s=300, interval_s=10)
    assert info, "RetrieveEnvironmentInfo never returned populated tail info after RequestEnvironmentInfo"
    for item in info:
        assert item["InfoType"] == "tail", f"expected InfoType 'tail', got {item['InfoType']!r}"
        assert item.get("Ec2InstanceId"), f"expected an Ec2InstanceId on each tail info item, got {item}"
        assert item.get("Message"), f"expected non-empty tail log Message, got {item}"


def _pick_solution_stack(eb: Any) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    if not stacks:
        raise AssertionError("no solution stacks available in this region")
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _env_name(ctx: Any) -> str:
    name = ctx.unique_name("eb-")
    return name[-40:] if len(name) > 40 else name


def _wait_for_env_status(ctx: Any, env_name: str, target_statuses: set, timeout_s: float = 900, interval_s: float = 15) -> str | None:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last_status = envs[0]["Status"]
            if last_status in target_statuses:
                return last_status
        time.sleep(interval_s)
    return last_status


def _ensure_instance_profile(ctx: Any) -> str:
    """CreateEnvironment fails with "Environment must have instance profile associated
    with it" on an account that has never bootstrapped the EB console's default
    aws-elasticbeanstalk-ec2-role -- the API does not create it for you. Provision a
    throwaway one here rather than depending on that ambient account state."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-ec2-role-")[:64]
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "request-then-retrieve-environment-info"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name))

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        profile = iam.get_instance_profile(InstanceProfileName=role_name)["InstanceProfile"]
        if profile["Roles"]:
            return role_name
        time.sleep(3)
    raise AssertionError(f"instance profile {role_name} never showed its attached role")


def _create_ready_environment(ctx: Any, option_settings: list | None = None, timeout_s: float = 1200) -> dict[str, str]:
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-ebapp-")
    tag = [{"Key": "sim2real", "Value": "request-then-retrieve-environment-info"}]
    eb.create_application(ApplicationName=app_name, Tags=tag)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    instance_profile = _ensure_instance_profile(ctx)
    env_name = _env_name(ctx)
    stack = _pick_solution_stack(eb)
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
    ]
    if option_settings:
        settings.extend(option_settings)

    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=settings,
        Tags=tag,
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))

    status = _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=timeout_s)
    if status != "Ready":
        events = eb.describe_events(ApplicationName=app_name, EnvironmentName=env_name, MaxRecords=20)["Events"]
        detail = "; ".join(f"[{e.get('Severity')}] {e.get('Message')}" for e in events)
        raise AssertionError(f"environment {env_name} did not reach Ready, last status={status}, events={detail}")
    return {"app_name": app_name, "env_name": env_name}


def _poll_environment_info(ctx: Any, env_name: str, timeout_s: float = 300, interval_s: float = 10) -> list:
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        last = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")["EnvironmentInfo"]
        if last:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
