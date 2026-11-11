"""create-environment-duplicate-name-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-environment-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateEnvironment with the name of a live environment fails with InvalidParameterValue
    "Environment <name> already exists." and creates nothing; once that environment is Terminated the
    identical call succeeds with a new EnvironmentId."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    eb.create_application(ApplicationName=app_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    instance_profile = _ensure_ec2_instance_profile(ctx)

    stack = _pick_solution_stack(ctx, eb)
    option_settings = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": instance_profile},
    ]

    # Positive control: the first CreateEnvironment call with this name succeeds.
    first = eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=option_settings,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))
    assert first["EnvironmentName"] == env_name, (
        f"positive control: expected EnvironmentName {env_name!r}, got {first.get('EnvironmentName')!r}"
    )
    first_id = first["EnvironmentId"]

    # Break exactly one thing: reusing the same (still-live) EnvironmentName is rejected.
    code, message = _error_code(
        lambda: eb.create_environment(
            ApplicationName=app_name,
            EnvironmentName=env_name,
            SolutionStackName=stack,
            OptionSettings=option_settings,
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue reusing a live EnvironmentName, got {code!r}"
    )
    expected = f"Environment {env_name} already exists."
    assert message == expected, (
        f"reusing a live EnvironmentName must say {expected!r}, got {message!r}"
    )

    # Effect absent: still exactly one non-terminated environment with this name/id, no
    # second environment silently sneaked in under the rejected call.
    envs = eb.describe_environments(
        ApplicationName=app_name, EnvironmentNames=[env_name], IncludeDeleted=False
    )["Environments"]
    live = [e for e in envs if e["Status"] != "Terminated"]
    assert len(live) == 1, f"expected exactly 1 live environment named {env_name!r}, found {len(live)}"
    assert live[0]["EnvironmentId"] == first_id, (
        f"expected the sole live environment to still be {first_id!r}, got {live[0]['EnvironmentId']!r}"
    )

    # Restore: terminate the blocking environment and wait for Terminated (not merely Terminating).
    # TerminateEnvironment refuses an environment still pending creation, so Ready comes first.
    _wait_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0)
    eb.terminate_environment(EnvironmentName=env_name)
    _wait_env_status(ctx, env_name, {"Terminated"}, timeout_s=900.0)

    # The identical call now succeeds, with a fresh EnvironmentId.
    second = eb.create_environment(
        ApplicationName=app_name,
        EnvironmentName=env_name,
        SolutionStackName=stack,
        OptionSettings=option_settings,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: eb.terminate_environment(EnvironmentName=env_name))
    assert second["EnvironmentName"] == env_name, (
        f"restore: expected EnvironmentName {env_name!r}, got {second.get('EnvironmentName')!r}"
    )
    second_id = second["EnvironmentId"]
    assert second_id != first_id, (
        f"expected a NEW EnvironmentId once {env_name!r} was freed by termination, got the same id {second_id!r}"
    )

    # Reach Ready before returning: on_cleanup's TerminateEnvironment hits the same "pending
    # creation" refusal proven above if it fires while this environment is still launching.
    _wait_env_status(ctx, env_name, {"Ready"}, timeout_s=900.0)


def _ensure_ec2_instance_profile(ctx: Any) -> str:
    """Create the EC2 instance role + instance profile a SingleInstance environment needs to
    actually launch. Real AWS: CreateEnvironment with no IamInstanceProfile returns success but the
    environment self-terminates within seconds -- it never reaches Ready -- because the account has
    no default EB instance profile (that default is created by the EB console on first use, not by
    the raw API)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eb-ec2-role-")
    profile_name = ctx.unique_name("sim2real-eb-ec2-profile-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"
        )
    )
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
    )
    return profile_name


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so an emulator accepting what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _pick_solution_stack(ctx: Any, eb: Any) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Amazon Linux" in s and "running" in s and "Docker" not in s:
            return s
    return stacks[0]


def _wait_env_status(ctx: Any, env_name: str, target_statuses: set, timeout_s: float, interval_s: float = 15.0):
    eb = ctx.client("elasticbeanstalk")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=True)["Environments"][0]
        if last.get("Status") in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {env_name!r} to reach {target_statuses}; last observed={last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
