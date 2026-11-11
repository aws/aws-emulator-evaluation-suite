"""retrieve-environment-info-log-content-round-trip."""
from __future__ import annotations

import json
import time
import urllib.request

from behavioral_harness import tags


def _routed_request(ctx, url, data=None, headers=None, **kwargs):
    """A urllib Request that reaches ``url`` on the target, with ``ctx.endpoint_route``'s headers."""
    target, route = ctx.endpoint_route(url)
    return urllib.request.Request(target, data=data, headers={**(headers or {}), **route}, **kwargs)


CHECK = "retrieve-environment-info-log-content-round-trip"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """RequestEnvironmentInfo(tail) then RetrieveEnvironmentInfo returns a tail entry for one of the environment's
    instances whose downloaded log is non-empty and matches its declared Content-Length."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-behav-taillog-")
    env_name = ctx.unique_name("sim2real-tail-")

    eb.create_application(ApplicationName=app_name)
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    stack = _pick_solution_stack(eb)
    instance_profile = _ensure_instance_profile(ctx)
    eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=_single_instance_settings(instance_profile),
    )
    _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=1200)

    real_instance_ids = {
        i["Id"]
        for i in eb.describe_environment_resources(EnvironmentName=env_name)["EnvironmentResources"]["Instances"]
    }
    assert real_instance_ids, f"environment {env_name} has no EC2 instances in DescribeEnvironmentResources"

    eb.request_environment_info(EnvironmentName=env_name, InfoType="tail")
    info = _wait_for_environment_info(eb, env_name, timeout_s=300)

    assert info["InfoType"] == "tail", f"expected InfoType 'tail', got {info['InfoType']!r}"
    assert info["Ec2InstanceId"] in real_instance_ids, (
        f"tail-log entry references instance {info['Ec2InstanceId']!r}, "
        f"not one of the environment's real instances {real_instance_ids}"
    )

    url = info["Message"]
    with urllib.request.urlopen(_routed_request(ctx, url), timeout=30) as resp:
        body = resp.read()
        declared_length = resp.headers.get("Content-Length")

    assert len(body) > 0, f"downloaded tail-log artifact from {url!r} was empty"
    if declared_length is not None:
        assert len(body) == int(declared_length), (
            f"downloaded {len(body)} bytes but Content-Length declared {declared_length}"
        )
    # A tail log is plain text; a truncated/binary-mangled transfer would
    # not decode cleanly.
    body.decode("utf-8", errors="strict")


def _single_instance_settings(instance_profile: str | None) -> list[dict[str, str]]:
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
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
    """Create an EC2 instance profile carrying the EB web-tier managed policy: on an account
    with no pre-existing default EB roles, CreateEnvironment stalls in Launching forever
    without one. Returns the profile name, or None if IAM is unreachable (an emulator that
    does not serve IAM), letting the service apply defaults."""
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


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _wait_for_env_status(eb, env_name: str, statuses, timeout_s: float = 900.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in statuses:
                return last
        time.sleep(interval_s)
    raise AssertionError(f"environment {env_name} never reached {statuses}; last={last}")


def _wait_for_environment_info(eb, env_name: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = eb.retrieve_environment_info(EnvironmentName=env_name, InfoType="tail").get("EnvironmentInfo", [])
        if items:
            return items[0]
        time.sleep(interval_s)
    raise AssertionError(f"no tail log info was ever produced for {env_name}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
