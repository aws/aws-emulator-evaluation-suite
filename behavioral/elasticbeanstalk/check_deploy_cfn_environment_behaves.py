"""deploy-cfn-environment-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import WaiterError

from behavioral_harness import tags

CHECK = "deploy-cfn-environment-behaves"
GROUP = "deploy"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An AWS::ElasticBeanstalk::Environment deployed via CloudFormation reaches a genuinely
    Ready environment whose instances pass DescribeInstancesHealth with real health data, not
    just CREATE_COMPLETE on the stack."""
    cfn = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")

    stack_name = ctx.unique_name("sim2real-eb-cfn-env-")
    app_name = ctx.unique_name("sim2real-eb-cfn-env-app-")
    env_name = _short_env_name(ctx, "ebcfe")
    stack_platform = _pick_solution_stack(ctx)

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "App": {"Type": "AWS::ElasticBeanstalk::Application", "Properties": {"ApplicationName": app_name}},
            "ServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "elasticbeanstalk.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
                        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
                    ],
                },
            },
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"],
                },
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {"Roles": [{"Ref": "InstanceRole"}]},
            },
            "Env": {
                "Type": "AWS::ElasticBeanstalk::Environment",
                "Properties": {
                    "ApplicationName": {"Ref": "App"},
                    "EnvironmentName": env_name,
                    "SolutionStackName": stack_platform,
                    "OptionSettings": [
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": {"Ref": "ServiceRole"}},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"},
                    ],
                },
            },
        },
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # the stack owns Application+Environment; deleting it tears both down, so no separate
    # elasticbeanstalk cleanup call is registered (that would race CloudFormation's own delete)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    try:
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1200})
    except WaiterError:
        pass

    stack_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert stack_status == "CREATE_COMPLETE", (
        f"stack ended in {stack_status}, not CREATE_COMPLETE: {_stack_failure_reason(cfn, stack_name)}"
    )

    env = _wait_env_status(ctx, env_name, {"Ready", "Terminated"}, timeout_s=900.0)
    assert env["Status"] == "Ready", (
        f"CloudFormation reported CREATE_COMPLETE but the underlying environment is {env['Status']!r}, not Ready"
    )

    health = _poll_until(
        lambda: eb.describe_instances_health(EnvironmentName=env_name, AttributeNames=["HealthStatus", "Color"]).get(
            "InstanceHealthList", []
        ),
        lambda instances: len(instances) > 0 and all(i.get("Color") != "Grey" for i in instances),
        timeout_s=600.0,
        interval_s=20.0,
    )
    for inst in health:
        assert inst.get("HealthStatus"), f"instance {inst.get('InstanceId')} has no HealthStatus"
        assert inst["Color"] in ("Green", "Yellow"), f"instance {inst.get('InstanceId')} health color is {inst['Color']!r}"


def _stack_failure_reason(cfn, stack_name: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception as e:
        return f"<could not fetch events: {e}>"
    reasons = []
    for e in events:
        if e.get("ResourceStatus", "").endswith("FAILED") and e.get("ResourceStatusReason"):
            reasons.append(f"{e.get('LogicalResourceId')}: {e['ResourceStatusReason']}")
    return " | ".join(reasons[:5]) if reasons else "<no failure reason found in events>"


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
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    raise AssertionError(f"condition not met within {timeout_s}s; last observed={value!r}")


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
