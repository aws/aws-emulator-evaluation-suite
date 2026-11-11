"""deploy-environment-cfn-then-managed-action-applies."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-environment-cfn-then-managed-action-applies"
GROUP = "server-side"
SERVICES = ["elasticbeanstalk"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An environment deployed through CloudFormation schedules an InstanceRefresh managed action that
    ApplyEnvironmentManagedAction runs to Completed in the history, on the same EnvironmentId."""
    eb = ctx.client("elasticbeanstalk")
    cfn = ctx.client("cloudformation")

    app_name = ctx.unique_name("sim2real-cfnmgd-app-")
    env_name = ctx.unique_name("sim2real-cfnm-")
    stack_name = ctx.unique_name("sim2real-cfnmgd-stack-")

    stack = _pick_solution_stack(eb)
    template = {
        "Resources": {
            "App": {
                "Type": "AWS::ElasticBeanstalk::Application",
                "Properties": {"ApplicationName": app_name},
            },
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
                    "ApplicationName": app_name,
                    "EnvironmentName": env_name,
                    "SolutionStackName": stack,
                    "OptionSettings": [
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                        {"Namespace": "aws:elasticbeanstalk:environment", "OptionName": "ServiceRole", "Value": {"Ref": "ServiceRole"}},
                        {"Namespace": "aws:autoscaling:launchconfiguration", "OptionName": "IamInstanceProfile", "Value": {"Ref": "InstanceProfile"}},
                        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "ManagedActionsEnabled", "Value": "true"},
                        {"Namespace": "aws:elasticbeanstalk:managedactions", "OptionName": "PreferredStartTime", "Value": "Sun:00:00"},
                        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "UpdateLevel", "Value": "minor"},
                        {"Namespace": "aws:elasticbeanstalk:managedactions:platformupdate", "OptionName": "InstanceRefreshEnabled", "Value": "true"},
                    ],
                },
                "DependsOn": ["App", "ServiceRole", "InstanceProfile"],
            },
        }
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    try:
        _wait_for_stack_status(cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=1200)
    except AssertionError as e:
        raise AssertionError(f"{e}; eb events: {_eb_failure_events(eb, env_name)}") from e

    env_before = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=300)
    environment_id = env_before["EnvironmentId"]
    date_updated_before = env_before["DateUpdated"]

    action = _wait_for_scheduled_action(eb, env_name, timeout_s=600)
    assert action["ActionType"] == "InstanceRefresh", (
        f"expected the CFN-provisioned environment's scheduled managed action to be "
        f"InstanceRefresh, got {action['ActionType']!r}"
    )

    eb.apply_environment_managed_action(EnvironmentName=env_name, ActionId=action["ActionId"])
    progressed = _wait_for_action_to_leave_scheduled(eb, env_name, action["ActionId"], timeout_s=180)
    assert progressed != "Scheduled", (
        f"expected ApplyEnvironmentManagedAction to force the action out of Scheduled within "
        f"180s via an independent read, but it was still {progressed!r}"
    )

    history_item = _wait_for_history_terminal(eb, env_name, action["ActionId"], timeout_s=1200)
    assert history_item["Status"] == "Completed", (
        f"managed action {action['ActionId']} reached a terminal history state of "
        f"{history_item['Status']!r}, not Completed"
    )

    final = _wait_for_env_status(eb, env_name, {"Ready"}, timeout_s=900)
    assert final["EnvironmentId"] == environment_id, (
        f"expected the same CFN-provisioned environment ({environment_id}) to still be answering "
        f"after the managed action, got EnvironmentId={final['EnvironmentId']!r}"
    )
    assert final["DateUpdated"] >= date_updated_before, (
        f"expected DateUpdated to advance past {date_updated_before!r} once the managed action "
        f"completed, got {final['DateUpdated']!r}"
    )


def _pick_solution_stack(eb) -> str:
    stacks = eb.list_available_solution_stacks()["SolutionStacks"]
    for s in stacks:
        if "Node.js" in s and "Amazon Linux 2023" in s:
            return s
    for s in stacks:
        if "Node.js" in s:
            return s
    return stacks[0]


def _wait_for_stack_status(cfn, stack_name: str, statuses, timeout_s: float = 1200.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last in statuses:
            return last
        if last.endswith("FAILED") or last == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} entered {last}: {_stack_failure_reason(cfn, stack_name)}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {statuses}; last={last}")


def _eb_failure_events(eb, env_name: str) -> str:
    try:
        events = eb.describe_events(EnvironmentName=env_name, Severity="ERROR", MaxRecords=10).get("Events", [])
    except Exception as e:
        return f"<could not fetch events: {e}>"
    return " | ".join(ev.get("Message", "") for ev in events) or "<no ERROR events found>"


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


def _delete_stack_and_wait(cfn, stack_name: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name).get("Stacks", [])
        if not stacks or stacks[0]["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(interval_s)


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


def _wait_for_scheduled_action(eb, env_name: str, timeout_s: float = 600.0, interval_s: float = 15.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(
            EnvironmentName=env_name, Status="Scheduled"
        ).get("ManagedActions", [])
        if actions:
            return actions[0]
        time.sleep(interval_s)
    raise AssertionError(f"no Scheduled managed action ever appeared for {env_name}")


def _wait_for_action_to_leave_scheduled(eb, env_name: str, action_id: str, timeout_s: float = 180.0, interval_s: float = 10.0) -> str:
    """Poll independently (never the apply call's own response) for the action to move
    off Scheduled -- either into Pending/Running, or straight into history if it finished
    fast. Returns the last observed status, or "gone" if it already left the live list."""
    deadline = time.monotonic() + timeout_s
    last_status = "Scheduled"
    while time.monotonic() < deadline:
        actions = eb.describe_environment_managed_actions(EnvironmentName=env_name).get("ManagedActions", [])
        match = next((a for a in actions if a["ActionId"] == action_id), None)
        if match is None:
            return "gone"
        last_status = match["Status"]
        if last_status != "Scheduled":
            return last_status
        time.sleep(interval_s)
    return last_status


def _wait_for_history_terminal(eb, env_name: str, action_id: str, timeout_s: float = 1200.0, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        items = eb.describe_environment_managed_action_history(EnvironmentName=env_name).get(
            "ManagedActionHistoryItems", []
        )
        for item in items:
            if item["ActionId"] == action_id and item["Status"] in ("Completed", "Failed", "Unknown"):
                return item
        time.sleep(interval_s)
    raise AssertionError(f"managed action {action_id} never reached a terminal history state")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
