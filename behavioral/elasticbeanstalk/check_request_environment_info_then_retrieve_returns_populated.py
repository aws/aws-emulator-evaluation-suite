"""request-environment-info-then-retrieve-returns-populated."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-environment-info-then-retrieve-returns-populated"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]

_TAGS = [{"Key": "sim2real", "Value": "true"}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RequestEnvironmentInfo triggers async server-side log collection; RetrieveEnvironmentInfo
    eventually returns a non-empty list with per-instance fetch URLs, each keyed to a real EC2
    instance of that environment."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-ebinfo-app-")
    env_name = _short_env_name(ctx, "ebinfo")

    eb.create_application(ApplicationName=app_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(ctx)
    _create_env_with_retry(
        ctx,
        eb,
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=_TAGS,
        OptionSettings=[
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
            {
                "Namespace": "aws:autoscaling:launchconfiguration",
                "OptionName": "IamInstanceProfile",
                "Value": _ensure_instance_profile(ctx),
            },
        ],
    )
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))

    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=1200.0)
    assert env["Status"] == "Ready", f"environment entered {env['Status']} instead of Ready"

    eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")

    info_list = _poll_until(
        lambda: eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail").get(
            "EnvironmentInfo", []
        ),
        lambda info: len(info) > 0,
        timeout_s=300.0,
        interval_s=15.0,
    )
    assert info_list, "RetrieveEnvironmentInfo never returned a non-empty EnvironmentInfo list"

    resources = eb.describe_environment_resources(EnvironmentName=env_name)["EnvironmentResources"]
    live_instance_ids = {i["Id"] for i in resources["Instances"]}
    assert live_instance_ids, "environment has no EC2 instances to correlate tail-log entries against"

    for item in info_list:
        assert item.get("InfoType") == "tail", f"expected InfoType 'tail', got {item.get('InfoType')!r}"
        assert item.get("Ec2InstanceId") in live_instance_ids, (
            f"EnvironmentInfo entry references unknown instance {item.get('Ec2InstanceId')!r}"
        )
        assert item.get("Message"), "EnvironmentInfo entry missing a fetch URL in Message"
        assert item["Message"].startswith("http"), "EnvironmentInfo Message is not a fetch URL"


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


def _short_env_name(ctx, tag: str) -> str:
    raw = ctx.unique_name("x")
    suffix = "".join(c for c in raw if c.isalnum())[-10:]
    return f"{tag}-{suffix}"[:40]


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while True:
        if predicate(value):
            return value
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()


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
