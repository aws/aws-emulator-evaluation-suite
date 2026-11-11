"""deploy-environment-via-cloudformation-serves-traffic."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-environment-via-cloudformation-serves-traffic"
GROUP = "deploy"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx: Any) -> None:
    """A CloudFormation-deployed AWS::ElasticBeanstalk::Environment comes up healthy: beyond stack
    CREATE_COMPLETE, environment health is Ready with Ok/Info and an instance reports Ok/Info."""
    cfn = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")

    app_name = ctx.unique_name("sim2real-eb4-app-")
    stack_name = ctx.unique_name("sim2real-eb4-stack-")
    solution_stack = _pick_solution_stack(ctx)

    template = {
        "Resources": {
            "App": {
                # AWS::ElasticBeanstalk::Application has no Tags property in CloudFormation
                # (unlike the boto3 CreateApplication API); the Environment and IAM role below
                # carry the tag so a tag search still finds this stack's resources.
                "Type": "AWS::ElasticBeanstalk::Application",
                "Properties": {"ApplicationName": app_name},
            },
            # AWS::ElasticBeanstalk::Environment has no default instance profile when
            # created via CloudFormation (unlike the console/EB-CLI flow, which
            # provisions "aws-elasticbeanstalk-ec2-role" implicitly) -- without one,
            # EB rejects the launch with "Environment must have instance profile
            # associated with it" and the stack rolls back within ~60s.
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier"],
                    "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
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
                    "SolutionStackName": solution_stack,
                    "OptionSettings": [
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:elasticbeanstalk:healthreporting:system", "OptionName": "SystemType", "Value": "enhanced"},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                    ],
                    "Tags": [{"Key": "sim2real", "Value": "elasticbeanstalk-behavioral"}],
                },
            },
        }
    }

    status = _deploy_cfn(ctx, stack_name, template, timeout_s=900.0, capabilities=["CAPABILITY_IAM"])
    if status != "CREATE_COMPLETE":
        reason = _stack_failure_reason(cfn, stack_name)
        eb_reason = _eb_failure_reason(eb, app_name)
        raise AssertionError(f"status={status} reason={reason[:600]} eb_events={eb_reason[:1200]}")
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=app_name, TerminateEnvByForce=True))

    envs = eb.describe_environments(ApplicationName=app_name, IncludeDeleted=False)["Environments"]
    assert len(envs) == 1
    env_name = envs[0]["EnvironmentName"]

    health = _wait_until(
        lambda: eb.describe_environment_health(EnvironmentName=env_name, AttributeNames=["All"]),
        lambda h: h.get("Status") == "Ready" and h.get("HealthStatus") in ("Ok", "Info"),
        timeout_s=600.0,
        interval_s=20.0,
    )
    assert health["Status"] == "Ready"
    assert health["HealthStatus"] in ("Ok", "Info")

    instances = _wait_until(
        lambda: eb.describe_instances_health(EnvironmentName=env_name, AttributeNames=["All"])["InstanceHealthList"],
        lambda lst: len(lst) >= 1 and any(i.get("HealthStatus") in ("Ok", "Info") for i in lst),
        timeout_s=300.0,
        interval_s=20.0,
    )
    assert any(i.get("HealthStatus") in ("Ok", "Info") for i in instances)


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    matches = [s for s in stacks if "Node.js" in s and "Docker" not in s]
    if not matches:
        raise AssertionError("no Node.js (non-Docker) solution stack available in this region")
    return matches[0]


def _wait_until(probe, predicate, timeout_s: float, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s; last observed={last!r}")


def _deploy_cfn(
    ctx, stack_name: str, template: dict, timeout_s: float = 900.0, on_failure: str | None = None, capabilities: list[str] | None = None
) -> str:
    cfn = ctx.client("cloudformation")
    kwargs: dict[str, Any] = {"StackName": stack_name, "TemplateBody": json.dumps(template)}
    if on_failure:
        kwargs["OnFailure"] = on_failure
    if capabilities:
        kwargs["Capabilities"] = capabilities

    def _cleanup():
        try:
            cfn.delete_stack(StackName=stack_name)
            _wait_stack_terminal(cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=timeout_s, allow_missing=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)
    return _wait_stack_terminal(
        cfn, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, timeout_s=timeout_s
    )


def _wait_stack_terminal(cfn, stack_name: str, terminal_statuses: set, timeout_s: float, allow_missing: bool = False) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except Exception:
            if allow_missing:
                return "DELETE_COMPLETE"
            raise
        if not stacks:
            if allow_missing:
                return "DELETE_COMPLETE"
        else:
            last = stacks[0]["StackStatus"]
            if last in terminal_statuses:
                return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s; last={last!r}")


def _eb_failure_reason(eb, app_name: str) -> str:
    try:
        events = eb.describe_events(ApplicationName=app_name, Severity="ERROR")["Events"]
    except Exception as e:
        return f"<could not fetch eb events: {e}>"
    return " | ".join(f"{e.get('EventDate')}: {e.get('Message')}" for e in events[:10]) or "<no ERROR events>"


def _stack_failure_reason(cfn, stack_name: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception as e:
        return f"<could not fetch events: {e}>"
    reasons = []
    for e in events:
        if e.get("ResourceStatus", "").endswith("FAILED") and e.get("ResourceStatusReason"):
            reasons.append(f"{e.get('LogicalResourceId')}: {e['ResourceStatusReason']}")
    if reasons:
        return " | ".join(reasons[:5])
    try:
        top = cfn.describe_stacks(StackName=stack_name)["Stacks"][0].get("StackStatusReason")
    except Exception:
        top = None
    return top or "<no failure reason found in events>"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
