"""cfn-deploy-iam-role-trusts-events-for-backup-notifications."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iam-role-trusts-events-for-backup-notifications"
GROUP = "permission-boundary"
SERVICES = ["backup", "events"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RoleName": {"Type": "String"},
            "StateMachineName": {"Type": "String"},
            "RuleName": {"Type": "String"},
        },
        "Resources": {
            "StateMachineExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "states.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    }
                },
            },
            "TargetStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineName": {"Ref": "StateMachineName"},
                    "RoleArn": {"Fn::GetAtt": ["StateMachineExecRole", "Arn"]},
                    "DefinitionString": json.dumps(
                        {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
                    ),
                },
            },
            "EventsInvokeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "AllowStartExecution",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "states:StartExecution",
                                        "Resource": {"Ref": "TargetStateMachine"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "BackupNotifyRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Ref": "RuleName"},
                    "EventPattern": {
                        "source": ["sim2real.backup.notifications"],
                        "detail-type": ["Backup Job State Change"],
                    },
                    "Targets": [
                        {
                            "Id": "StateMachineTarget",
                            "Arn": {"Ref": "TargetStateMachine"},
                            "RoleArn": {"Fn::GetAtt": ["EventsInvokeRole", "Arn"]},
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "RoleArn": {"Value": {"Fn::GetAtt": ["EventsInvokeRole", "Arn"]}},
            "StateMachineArn": {"Value": {"Ref": "TargetStateMachine"}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["BackupNotifyRule", "Arn"]}},
        },
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed role trusting events.amazonaws.com is declared correctly and is usable:
    EventBridge assumes it to start a Step Functions execution when a custom-source event
    shaped like a "Backup Job State Change" notification matches the rule."""
    params = {
        "RoleName": _xname(ctx, "evrole"),
        "StateMachineName": _xname(ctx, "sm"),
        "RuleName": _xname(ctx, "rule"),
    }
    stack = _deploy_cfn(ctx, _TEMPLATE, parameters=params, timeout_s=180)
    outputs = stack["outputs"]
    role_arn = outputs["RoleArn"]
    sm_arn = outputs["StateMachineArn"]
    rule_name = params["RuleName"]

    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    role = iam.get_role(RoleName=role_name)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    principals = [
        stmt["Principal"].get("Service")
        for stmt in trust_doc["Statement"]
        if stmt.get("Effect") == "Allow"
    ]
    assert "events.amazonaws.com" in principals, f"trust policy missing events.amazonaws.com: {trust_doc}"

    events = ctx.client("events")
    rule_desc = events.describe_rule(Name=rule_name)
    assert rule_desc["State"] == "ENABLED"

    sfn = ctx.client("stepfunctions")
    before = {
        e["executionArn"]
        for e in sfn.list_executions(stateMachineArn=sm_arn)["executions"]
    }

    # A freshly-created IAM role can lag STS propagation, so EventBridge's first invoke attempt
    # may transiently fail with AccessDenied and only succeed on its internal retry. Re-emit the
    # triggering event on each poll tick rather than sending it once and waiting out that retry
    # window blind.
    sent_markers: list[str] = []

    def _emit_and_check_new_executions():
        marker = ctx.unique_name("sim2real-job-")
        sent_markers.append(marker)
        events.put_events(
            Entries=[
                {
                    "Source": "sim2real.backup.notifications",
                    "DetailType": "Backup Job State Change",
                    "Detail": json.dumps({"backupJobId": marker, "state": "COMPLETED"}),
                }
            ]
        )
        current = sfn.list_executions(stateMachineArn=sm_arn)["executions"]
        return [e for e in current if e["executionArn"] not in before]

    new_execs = _poll_until(
        _emit_and_check_new_executions,
        lambda execs: len(execs) >= 1,
        timeout_s=150,
        interval_s=10.0,
        description="EventBridge (via trusted role) starting a Step Functions execution",
    )
    exec_arn = new_execs[0]["executionArn"]
    # The rule's target has no Input/InputTransformer, so EventBridge's default behavior must
    # have relayed the actual matched event -- not a stub -- as this execution's input: proof
    # of end-to-end content propagation through the trusted role, not just that some execution
    # started.
    exec_input = json.loads(sfn.describe_execution(executionArn=exec_arn)["input"])
    assert exec_input.get("detail", {}).get("backupJobId") in sent_markers, (
        f"execution input {exec_input} does not correlate to any event this check emitted: {sent_markers}"
    )
    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "ABORTED", "TIMED_OUT"),
        timeout_s=60,
        interval_s=2.0,
        description=f"execution {exec_arn} reach terminal status",
    )
    assert final["status"] == "SUCCEEDED"


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": _XSVC_PREFIX.rstrip("-")},
    ]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ValidationError" and "does not exist" in error.get("Message", ""):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
