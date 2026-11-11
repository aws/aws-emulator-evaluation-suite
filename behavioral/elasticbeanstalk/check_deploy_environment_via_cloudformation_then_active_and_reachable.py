"""deploy-environment-via-cloudformation-then-active-and-reachable."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-environment-via-cloudformation-then-active-and-reachable"
GROUP = "deploy"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx: Any) -> None:
    """A CloudFormation stack deploying AWS::ElasticBeanstalk::{Application,Environment}
    reaches CREATE_COMPLETE, and the resulting environment is independently observed Ready
    with its CNAME registered (CheckDNSAvailability reports it as taken)."""
    eb = ctx.client("elasticbeanstalk")
    ctx.client("cloudformation")

    app_name = ctx.unique_name("sim2real-eb-app-")
    env_name = ctx.unique_name("sim2real-eb-env-")
    cname_prefix = ctx.unique_name("sim2real-eb-cname-").lower().replace("_", "-")
    stack_name = ctx.unique_name("sim2real-eb-stack-")
    stack_ns = _pick_solution_stack(ctx)

    template = {
        "Resources": {
            "App": {
                "Type": "AWS::ElasticBeanstalk::Application",
                "Properties": {"ApplicationName": app_name},
            },
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
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
                    "CNAMEPrefix": cname_prefix,
                    "SolutionStackName": stack_ns,
                    "OptionSettings": [
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "InstanceType", "Value": "t3.micro"},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                    ],
                },
            },
        }
    }

    try:
        _deploy_cfn(ctx, stack_name, template, timeout_s=1500, capabilities=["CAPABILITY_IAM"])
    except AssertionError as exc:
        raise AssertionError(f"{exc}; EB-level events for {env_name}: {_eb_events(eb, env_name)}") from exc

    envs = eb.describe_environments(EnvironmentNames=[env_name], IncludeDeleted=False)["Environments"]
    assert len(envs) == 1, f"expected exactly one environment named {env_name}, found {len(envs)}"
    assert envs[0]["Status"] == "Ready", f"environment status is {envs[0]['Status']!r}, expected Ready"

    dns = eb.check_dns_availability(CNAMEPrefix=cname_prefix)
    assert dns["Available"] is False, "CNAME prefix used by the deployed environment reports as still available"
    # CheckDNSAvailability omits FullyQualifiedCNAME entirely when Available is False (measured on
    # real AWS) -- it is returned only on the AVAILABLE answer. DescribeEnvironments's own CNAME is
    # the independent read that carries the hostname while the prefix is held.
    assert envs[0]["CNAME"].startswith(cname_prefix + "."), (
        f"environment CNAME {envs[0].get('CNAME')!r} does not start with its own prefix {cname_prefix!r}"
    )


def _pick_solution_stack(ctx: Any) -> str:
    eb = ctx.client("elasticbeanstalk")
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    if not stacks:
        raise AssertionError("account/region has no available Elastic Beanstalk solution stacks")
    for s in stacks:
        if "Amazon Linux 2" in s and "Node.js" in s:
            return s
    return stacks[0]


def _deploy_cfn(
    ctx: Any, stack_name: str, template: dict[str, Any], timeout_s: float = 900.0, capabilities: list[str] | None = None
) -> None:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                resp = cfn.describe_stacks(StackName=stack_name)
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] != "StackNotFoundException" and not (
                    err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
                ):
                    raise
                return
            stacks = resp.get("Stacks", [])
            if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
                return
            time.sleep(15)

    kwargs: dict[str, Any] = {
        "StackName": stack_name,
        "TemplateBody": json.dumps(template),
        "OnFailure": "DELETE",
        "Tags": [{"Key": "sim2real", "Value": "deploy-environment-via-cloudformation-then-active-and-reachable"}],
    }
    if capabilities:
        kwargs["Capabilities"] = capabilities
    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status == "CREATE_COMPLETE":
            return
        if status in ("CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_IN_PROGRESS", "DELETE_IN_PROGRESS"):
            reason = _stack_failure_reason(cfn, stack_name)
            raise AssertionError(f"stack {stack_name} entered failure status {status!r}: {reason}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never reached CREATE_COMPLETE, last status {status!r}")


def _eb_events(eb: Any, env_name: str) -> str:
    try:
        events = eb.describe_events(EnvironmentName=env_name, MaxRecords=20)["Events"]
    except Exception as exc:  # noqa: BLE001 — the reason lookup itself is best-effort
        return f"<could not fetch EB events: {exc}>"
    if not events:
        return "<no EB events recorded>"
    return " | ".join(f"{e['Severity']}: {e['Message']}" for e in events[:10])


def _stack_failure_reason(cfn: Any, stack_name: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except Exception as exc:  # noqa: BLE001 — the reason lookup itself is best-effort
        return f"<could not fetch stack events: {exc}>"
    reasons = [
        f"{e.get('LogicalResourceId')}: {e['ResourceStatusReason']}"
        for e in events
        if e.get("ResourceStatus", "").endswith("FAILED") and e.get("ResourceStatusReason")
    ]
    return " | ".join(reasons[:5]) if reasons else "<no failure reason found in stack events>"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
