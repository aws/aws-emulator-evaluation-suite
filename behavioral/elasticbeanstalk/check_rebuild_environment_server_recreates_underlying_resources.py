"""rebuild-environment-server-recreates-underlying-resources."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rebuild-environment-server-recreates-underlying-resources"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RebuildEnvironment replaces the environment's EC2 instances (post-rebuild IDs disjoint from the
    pre-rebuild set) while EnvironmentName and CNAME stay unchanged."""
    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    svc_role_name, _svc_role_arn, ec2_profile_name = _create_eb_roles(ctx)
    solution_stack = _pick_solution_stack(eb)
    _create_environment(ctx, eb, app_name, env_name, svc_role_name, ec2_profile_name, solution_stack_name=solution_stack)
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))
    _wait_env_status(eb, env_name, targets={"Ready"}, timeout_s=900.0)

    resources_before = eb.describe_environment_resources(EnvironmentName=env_name)["EnvironmentResources"]
    instance_ids_before = {i["Id"] for i in resources_before.get("Instances", [])}
    env_before = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
    cname_before = env_before["CNAME"]
    assert instance_ids_before, "expected at least one running instance before rebuild"

    eb.rebuild_environment(EnvironmentName=env_name)

    # RebuildEnvironment transitions Ready -> Launching -> Ready; wait past the initial dip
    # before polling for the final settled state so we don't read a stale "Ready" from before
    # the rebuild was accepted.
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        env = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
        if env["Status"] != "Ready":
            break
        time.sleep(5.0)

    _wait_env_status(eb, env_name, targets={"Ready"}, timeout_s=900.0)

    resources_after = eb.describe_environment_resources(EnvironmentName=env_name)["EnvironmentResources"]
    instance_ids_after = {i["Id"] for i in resources_after.get("Instances", [])}
    env_after = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"][0]
    cname_after = env_after["CNAME"]

    assert instance_ids_after, "expected at least one running instance after rebuild"
    assert instance_ids_before.isdisjoint(instance_ids_after), (
        f"rebuild did not recreate instances: before={instance_ids_before} after={instance_ids_after}"
    )
    assert env_after["EnvironmentName"] == env_name, (
        f"expected EnvironmentName to survive rebuild unchanged: expected={env_name} actual={env_after['EnvironmentName']}"
    )
    assert cname_after == cname_before, f"CNAME changed across rebuild: {cname_before} -> {cname_after}"


def _create_eb_roles(ctx) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-ebrole-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

    svc_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    ec2_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )

    role_tags = [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}]

    svc_role_arn = iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust, Tags=role_tags)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))

    iam.create_instance_profile(InstanceProfileName=ec2_name, Tags=role_tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    return svc_name, svc_role_arn, ec2_name


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for stack in stacks:
        if "Amazon Linux 2" in stack and "Docker" not in stack and "Windows" not in stack:
            return stack
    return stacks[0]


def _create_environment(
    ctx,
    eb,
    app_name: str,
    env_name: str,
    svc_role_name: str,
    ec2_profile_name: str,
    solution_stack_name: str | None = None,
    platform_arn: str | None = None,
    extra_options: list[dict[str, str]] | None = None,
):
    options = [
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
    ]
    if extra_options:
        options.extend(extra_options)
    kwargs: dict[str, Any] = {
        "ApplicationName": app_name,
        "EnvironmentName": env_name,
        "OptionSettings": options,
        "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    }
    if platform_arn:
        kwargs["PlatformArn"] = platform_arn
    else:
        kwargs["SolutionStackName"] = solution_stack_name

    # Bounded retry for IAM eventual consistency: the roles above were just created, and
    # Elastic Beanstalk's own AssumeRole/PassRole check against them can lag briefly.
    deadline = time.monotonic() + 80
    while True:
        try:
            return eb.create_environment(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


def _wait_env_status(eb, env_name: str, targets: set[str], timeout_s: float = 900.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False).get("Environments", [])
        if envs:
            last = envs[0]
            if last["Status"] in targets:
                return last
        time.sleep(interval_s)
    status = last.get("Status") if last else None
    raise AssertionError(f"environment {env_name} did not reach {targets} within {timeout_s}s (last status={status})")


def _terminate_env_and_wait(eb, env_name: str, timeout_s: float = 600.0) -> None:
    """Teardown: terminate the environment and wait for Terminated, so its instance and Elastic IP
    are released; re-issued while EB refuses it mid-operation (invalid state, pending deployment).
    An environment already gone counts as terminated."""
    deadline = time.monotonic() + timeout_s
    while True:
        envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
        if not envs or envs[0]["Status"] == "Terminated":
            return
        if envs[0]["Status"] != "Terminating":
            try:
                eb.terminate_environment(EnvironmentName=env_name)
            except ClientError as exc:
                msg = exc.response["Error"].get("Message", "")
                if "not found" in msg.lower():
                    return
                if not ("invalid state" in msg or "pending deployment" in msg) or time.monotonic() >= deadline:
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"environment {env_name} not terminated within {timeout_s:.0f}s")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
