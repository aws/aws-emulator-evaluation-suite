"""deploy-cloudformation-invalid-platform-arn-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cloudformation-invalid-platform-arn-rejected"
GROUP = "deploy"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx: Any) -> None:
    """A CloudFormation AWS::ElasticBeanstalk::Environment with a nonexistent PlatformArn ends CREATE_FAILED with a
    platform failure reason and no environment, while the same stack on a valid platform creates one environment."""
    cfn = ctx.client("cloudformation")
    eb = ctx.client("elasticbeanstalk")

    bad_app_name = ctx.unique_name("sim2real-eb7-bad-app-")
    bad_stack_name = ctx.unique_name("sim2real-eb7-bad-stack-")
    bogus_platform_arn = f"arn:aws:elasticbeanstalk:{ctx.region}::platform/Sim2Real-Nonexistent-Platform/999.999.999"

    bad_template = {
        "Resources": {
            "App": {"Type": "AWS::ElasticBeanstalk::Application", "Properties": {"ApplicationName": bad_app_name}},
            "Env": {
                "Type": "AWS::ElasticBeanstalk::Environment",
                "Properties": {
                    "ApplicationName": {"Ref": "App"},
                    "PlatformArn": bogus_platform_arn,
                    "OptionSettings": [
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": {"Ref": "ServiceRole"}},
                    ],
                },
            },
            **_eb_iam_resources(),
        }
    }
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=bad_app_name, TerminateEnvByForce=True))

    bad_status = _deploy_cfn(ctx, bad_stack_name, bad_template, timeout_s=300.0, on_failure="DO_NOTHING")
    assert bad_status == "CREATE_FAILED", f"expected the bogus-platform stack to end CREATE_FAILED, got {bad_status!r}"

    failures = _stack_failure_reasons(cfn, bad_stack_name)
    assert "Env" in failures, (
        f"expected the Env resource itself to be the one that fails on the bogus PlatformArn, but "
        f"the stack failed before Env was ever attempted: {failures!r}"
    )
    reason = failures["Env"] or ""
    assert "platform" in reason.lower(), (
        f"Env failed for a reason unrelated to the bogus PlatformArn (must name the cause 'platform' "
        f"to distinguish this from an unrelated failure like a missing instance profile): {reason!r}"
    )

    # Effect absent: no environment was ever created under the bad application.
    envs = eb.describe_environments(ApplicationName=bad_app_name, IncludeDeleted=False)["Environments"]
    assert envs == [], f"expected no environment under {bad_app_name!r}, got {envs!r}"

    # Positive control: an otherwise-identical stack with a valid platform succeeds.
    good_app_name = ctx.unique_name("sim2real-eb7-good-app-")
    good_stack_name = ctx.unique_name("sim2real-eb7-good-stack-")
    good_template = {
        "Resources": {
            "App": {"Type": "AWS::ElasticBeanstalk::Application", "Properties": {"ApplicationName": good_app_name}},
            "Env": {
                "Type": "AWS::ElasticBeanstalk::Environment",
                "Properties": {
                    "ApplicationName": {"Ref": "App"},
                    "SolutionStackName": _pick_solution_stack(ctx),
                    "OptionSettings": [
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": {"Ref": "ServiceRole"}},
                    ],
                },
            },
            **_eb_iam_resources(),
        }
    }
    ctx.on_cleanup(lambda: eb.delete_application(ApplicationName=good_app_name, TerminateEnvByForce=True))

    good_status = _deploy_cfn(ctx, good_stack_name, good_template, timeout_s=900.0)
    assert good_status == "CREATE_COMPLETE", f"positive-control stack ended {good_status!r}, not CREATE_COMPLETE"
    good_envs = eb.describe_environments(ApplicationName=good_app_name, IncludeDeleted=False)["Environments"]
    assert len(good_envs) == 1, f"expected exactly 1 environment under {good_app_name!r}, got {good_envs!r}"


def _eb_iam_resources() -> dict:
    """Same IAM wiring (service role + instance role + instance profile) for both the
    negative and positive stacks, so a fresh account with no ambient EB default roles
    does not make the positive control fail for a reason unrelated to PlatformArn."""
    return {
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
    }


def _stack_failure_reasons(cfn, stack_name: str) -> dict[str, str]:
    """Logical-resource-id -> its first FAILED ResourceStatusReason, read from stack events.
    A resource that never started (e.g. one CloudFormation never reached because an earlier
    dependency failed first) has no StackResource record at all, so describe_stack_resource
    raises rather than reporting absence -- this reads the event stream instead."""
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    reasons: dict[str, str] = {}
    for e in events:
        logical_id = e.get("LogicalResourceId")
        if e.get("ResourceStatus", "").endswith("FAILED") and logical_id not in reasons:
            reasons[logical_id] = e.get("ResourceStatusReason", "")
    return reasons


def _pick_solution_stack(ctx) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    matches = [s for s in stacks if "Node.js" in s and "Docker" not in s]
    if not matches:
        raise AssertionError("no Node.js (non-Docker) solution stack available in this region")
    return matches[0]


def _deploy_cfn(ctx, stack_name: str, template: dict, timeout_s: float = 900.0, on_failure: str | None = None) -> str:
    cfn = ctx.client("cloudformation")
    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": json.dumps(template),
        "Capabilities": ["CAPABILITY_IAM"],
    }
    if on_failure:
        kwargs["OnFailure"] = on_failure

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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
