"""e2e-request-and-retrieve-environment-info-flow."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-request-and-retrieve-environment-info-flow"
GROUP = "e2e"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestEnvironmentInfo(tail) on a Ready environment makes RetrieveEnvironmentInfo return tail
    items, each with an Ec2InstanceId and a log-download Message, proving async collection works."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")

    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: _delete_app(eb, app_name))

    stack = _pick_solution_stack(eb)
    instance_profile = _ensure_instance_profile(ctx)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=_single_instance_settings(instance_profile),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))

    # A real EC2 instance is provisioned; reaching Ready can take 5-15 minutes.
    env = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900.0)
    assert env["Status"] == "Ready", f"expected environment status Ready, got {env['Status']!r}"

    eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")

    info_items = _poll_until_info(eb, env_name, timeout_s=300.0)
    assert len(info_items) >= 1, (
        f"expected RetrieveEnvironmentInfo to return at least one tail-log item, got {info_items!r}"
    )
    for item in info_items:
        assert item["InfoType"] == "tail", f"expected InfoType 'tail', got {item.get('InfoType')!r}"
        assert item.get("Ec2InstanceId"), f"expected a non-empty Ec2InstanceId, got {item!r}"
        assert item.get("Message"), f"expected a non-empty Message (log download URL), got {item!r}"




def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Python" in s:
            return s
    return stacks[0]


def _single_instance_settings(instance_profile: str | None) -> list[dict[str, str]]:
    settings = [
        {
            "Namespace": "aws:elasticbeanstalk:environment",
            "OptionName": "EnvironmentType",
            "Value": "SingleInstance",
        },
        {
            "Namespace": "aws:autoscaling:launchconfiguration",
            "OptionName": "InstanceType",
            "Value": "t3.micro",
        },
    ]
    if instance_profile:
        settings.append(
            {
                "Namespace": "aws:autoscaling:launchconfiguration",
                "OptionName": "IamInstanceProfile",
                "Value": instance_profile,
            }
        )
    return settings


def _ensure_instance_profile(ctx) -> str | None:
    """Create an instance profile with the EB web-tier policy; without one CreateEnvironment can
    stall in Launching. Returns the profile name, or None when IAM is unreachable."""
    try:
        iam = ctx.client("iam")
        iam.list_roles(MaxItems=1)
    except Exception:
        return None

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
    _wait_instance_profile_visible(iam, profile_name, timeout_s=30.0)
    return profile_name


def _wait_instance_profile_visible(iam, profile_name: str, timeout_s: float, interval_s: float = 3.0) -> None:
    """IAM is eventually consistent: poll GetInstanceProfile until it is visible, bounding
    the wait EB itself needs before it can resolve the new principal."""
    deadline = time.monotonic() + timeout_s
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            return
        except Exception as exc:
            last_error = exc
            time.sleep(interval_s)
    raise AssertionError(f"instance profile {profile_name} never became visible via IAM: {last_error}")


def _wait_for_env_status(
    eb,
    env_name: str,
    target_statuses: set[str],
    timeout_s: float = 900.0,
    interval_s: float = 15.0,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        envs = resp.get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in target_statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {target_statuses}; last={last}")


def _poll_until_info(
    eb, env_name: str, timeout_s: float = 300.0, interval_s: float = 15.0
) -> list[dict[str, Any]]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail")
        items = resp.get("EnvironmentInfo", [])
        if items:
            return items
        time.sleep(interval_s)
    raise AssertionError("RetrieveEnvironmentInfo never returned tail log entries")


def _terminate_env_and_wait(eb, env_name: str, timeout_s: float = 600.0) -> None:
    try:
        eb.terminate_environment(EnvironmentName=env_name)
    except ClientError as err:
        # Already terminating or already gone: both are the wanted state; anything else re-raises.
        if err.response["Error"]["Code"] != "InvalidParameterValue":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)
        envs = resp.get("Environments", [])
        if not envs or envs[0]["Status"] == "Terminated":
            return
        time.sleep(2.0)
    raise AssertionError(f"environment {env_name} did not reach Terminated within {timeout_s:.0f}s")


def _delete_app(eb, app_name: str) -> None:
    eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
