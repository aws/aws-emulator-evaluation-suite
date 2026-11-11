"""rebuild-environment-cycles-through-launching-to-ready."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "rebuild-environment-cycles-through-launching-to-ready"
GROUP = "state-machine"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RebuildEnvironment moves the environment through Updating before it settles back to Ready.

    The settled environment runs on an instance set disjoint from the one it had before the call.
    """
    eb = ctx.client("elasticbeanstalk")
    env = _create_ready_environment(ctx)
    env_name = env["env_name"]

    def _instances():
        res = eb.describe_environment_resources(EnvironmentName=env_name)["EnvironmentResources"]
        return {i["Id"] for i in res["Instances"]}

    before = _instances()
    assert before, f"a Ready SingleInstance environment must report its instance, got {before!r}"

    eb.rebuild_environment(EnvironmentName=env_name)

    updating_status = _wait_for_env_status(ctx, env_name, {"Updating"}, timeout_s=120, interval_s=3)
    assert updating_status == "Updating", (
        f"expected RebuildEnvironment to move the environment through a transitional "
        f"Updating status before Ready, last observed {updating_status!r}"
    )

    deadline = time.monotonic() + 1200
    while True:
        status = eb.describe_environments(EnvironmentNames=[env_name])["Environments"][0]["Status"]
        after = _instances() if status == "Ready" else set()
        if status == "Ready" and after and after.isdisjoint(before):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"after RebuildEnvironment, {env_name} must settle Ready on a new instance within "
                f"1200s; last Status {status!r}, instances {after!r}, before {before!r}")
        time.sleep(2)


def _pick_solution_stack(eb: Any) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    if not stacks:
        raise AssertionError("no solution stacks available in this region")
    for stack in stacks:
        if "Amazon Linux 2" in stack and "Docker" not in stack and "Windows" not in stack:
            return stack
    return stacks[0]


def _env_name(ctx: Any) -> str:
    name = ctx.unique_name("eb-")
    return name[-40:] if len(name) > 40 else name


def _wait_for_env_status(ctx: Any, env_name: str, target_statuses: set, timeout_s: float = 900, interval_s: float = 2) -> str | None:
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


def _create_eb_roles(ctx: Any) -> tuple[str, str]:
    """A fresh account has neither `aws-elasticbeanstalk-service-role` nor
    `aws-elasticbeanstalk-ec2-role` (the EB console auto-creates these; the API does not),
    so create-and-attach explicitly rather than depending on that ambient default."""
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

    iam.create_role(RoleName=svc_name, AssumeRolePolicyDocument=svc_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=ec2_trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    iam.attach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=ec2_name, PolicyArn="arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"))

    iam.create_instance_profile(InstanceProfileName=ec2_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    return svc_name, ec2_name


def _create_ready_environment(ctx: Any, option_settings: list | None = None, timeout_s: float = 900) -> dict[str, str]:
    from botocore.exceptions import ClientError

    eb = ctx.client("elasticbeanstalk")
    app_name = ctx.unique_name("sim2real-ebapp-")
    eb.create_application(
        ApplicationName=app_name,
        Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
    )
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    svc_role_name, ec2_profile_name = _create_eb_roles(ctx)
    env_name = _env_name(ctx)
    stack = _pick_solution_stack(eb)
    settings = [
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": svc_role_name},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": ec2_profile_name},
        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
    ]
    if option_settings:
        settings.extend(option_settings)

    # Retried while the just-created roles are not yet usable by Elastic Beanstalk.
    deadline = time.monotonic() + 80
    while True:
        try:
            eb.create_environment(
                ApplicationName=app_name,
                EnvironmentName=env_name,
                SolutionStackName=stack,
                OptionSettings=settings,
                Tags=[{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "InsufficientPrivilegesException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)
    ctx.on_cleanup(lambda: _terminate_env_and_wait(eb, env_name))

    status = _wait_for_env_status(ctx, env_name, {"Ready"}, timeout_s=timeout_s)
    if status != "Ready":
        raise AssertionError(f"environment {env_name} did not reach Ready, last status={status}")
    return {"app_name": app_name, "env_name": env_name}


def _terminate_env_and_wait(eb, env_name: str, timeout_s: float = 600.0) -> None:
    """Teardown: terminate the environment and wait for Terminated, so its instance and Elastic IP
    are released; re-issued while EB refuses it mid-operation (invalid state, pending deployment).
    An environment already gone counts as terminated."""
    from botocore.exceptions import ClientError
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
