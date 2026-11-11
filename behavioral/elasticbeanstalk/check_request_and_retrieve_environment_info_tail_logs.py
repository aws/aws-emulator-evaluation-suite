"""request-and-retrieve-environment-info-tail-logs."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-and-retrieve-environment-info-tail-logs"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RequestEnvironmentInfo followed by RetrieveEnvironmentInfo returns a non-empty tail-log
    bundle that references a real EC2 instance of the requested, running environment.
    """
    eb = ctx.client("elasticbeanstalk")

    app_name = ctx.unique_name("sim2real-ebinfo-app-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)

    env_name = ctx.unique_name("sim2real-ebinfo-env-")
    _create_env_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
        OptionSettings=[
            {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
            {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": _ensure_instance_profile(ctx)},
        ],
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))

    _wait_for_environment_ready(eb, env_name, timeout_s=1200.0)

    eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")

    info = _wait_for_environment_info(eb, env_name, timeout_s=180.0)
    assert len(info) > 0, f"RetrieveEnvironmentInfo never returned a tail-log bundle, got {info!r}"

    instance_ids = {i["Id"] for i in eb.describe_environment_resources(
        EnvironmentName=env_name
    )["EnvironmentResources"]["Instances"]}
    assert instance_ids, "environment has no EC2 instances to correlate against"

    for item in info:
        assert item["Ec2InstanceId"] in instance_ids, (
            f"tail-log entry references unknown instance {item['Ec2InstanceId']!r}"
        )
        assert item.get("Message"), "tail-log entry has no message/log content"


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


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


def _create_env_with_retry(ctx, eb, **kwargs) -> dict:
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


def _terminate_env_and_wait(eb, env_name: str, timeout_s: float = 900.0) -> None:
    """Terminate the environment and wait until it is gone, so the instance profile it holds
    can be deleted. An environment EB already removed counts as terminated."""
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as exc:
        if "not found" not in str(exc).lower():
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if not envs or envs[0]["Status"] == "Terminated":
            return
        time.sleep(2.0)
    raise AssertionError(f"environment {env_name} not terminated within {timeout_s}s")


def _wait_for_environment_ready(eb, env_name: str, timeout_s: float = 900.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if not envs:
            time.sleep(interval_s)
            continue
        env = envs[0]
        last_status = env["Status"]
        if last_status == "Ready":
            return env
        if last_status in ("Terminating", "Terminated"):
            raise AssertionError(f"environment unexpectedly reached status {last_status}")
        time.sleep(interval_s)
    raise AssertionError(f"environment never reached Ready (last status: {last_status})")


def _wait_for_environment_info(eb, env_name: str, timeout_s: float = 180.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        info = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")["EnvironmentInfo"]
        if info:
            return info
        time.sleep(interval_s)
    raise AssertionError(f"RetrieveEnvironmentInfo never populated a tail-log bundle within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
