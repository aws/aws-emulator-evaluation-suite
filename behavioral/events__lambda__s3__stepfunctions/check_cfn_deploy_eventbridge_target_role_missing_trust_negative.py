"""cfn-deploy-eventbridge-target-role-missing-trust-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-eventbridge-target-role-missing-trust-negative"
GROUP = "overly-permissive"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge target role whose trust policy omits events.amazonaws.com lets the rule
    fire (PutEvents succeeds) but never actually starts an execution; once the trust policy is
    corrected, an identical event does start (and complete) an execution."""
    definition = {"StartAt": "Echo", "States": {"Echo": {"Type": "Pass", "End": True}}}

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SfnRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    }
                },
            },
            "NegStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]},
                    "DefinitionString": json.dumps(definition),
                },
            },
            "EventsTargetRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "EventsRoleName"},
                    # BROKEN: trusts lambda.amazonaws.com, NOT events.amazonaws.com — the rule
                    # can never assume this role to invoke the target.
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "start-execution",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "states:StartExecution",
                                "Resource": {"Ref": "NegStateMachine"},
                            }],
                        },
                    }],
                },
            },
            "NegRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["custom.negtrust"],
                        "detail-type": ["NegTrustTest"],
                    },
                    "Targets": [{
                        "Id": "SfnTarget",
                        "Arn": {"Ref": "NegStateMachine"},
                        "RoleArn": {"Fn::GetAtt": ["EventsTargetRole", "Arn"]},
                    }],
                },
            },
        },
        "Parameters": {"EventsRoleName": {"Type": "String"}},
        "Outputs": {
            "StateMachineArn": {"Value": {"Ref": "NegStateMachine"}},
            "EventsRoleName": {"Value": {"Ref": "EventsTargetRole"}},
        },
    }

    role_name = ctx.unique_name("sim2real-xsvc-evrole-")
    result = _deploy_cfn(ctx, json.dumps(template), parameters={"EventsRoleName": role_name})
    sm_arn = result["outputs"]["StateMachineArn"]

    events = ctx.client("events")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    marker1 = ctx.unique_name("negtrust-")
    events.put_events(Entries=[{
        "Source": "custom.negtrust",
        "DetailType": "NegTrustTest",
        "Detail": json.dumps({"marker": marker1}),
    }])

    # Bounded wait for a would-be invocation, then assert it never happened.
    def _executions_with_marker(marker):
        execs = sfn.list_executions(stateMachineArn=sm_arn, maxResults=50).get("executions", [])
        found = []
        for e in execs:
            desc = sfn.describe_execution(executionArn=e["executionArn"])
            try:
                inp = json.loads(desc["input"])
            except (json.JSONDecodeError, KeyError):
                continue
            if inp.get("detail", {}).get("marker") == marker:
                found.append(desc)
        return found

    def _assert_never_starts_within(marker, window_s, interval_s=4.0):
        deadline = time.monotonic() + window_s
        while time.monotonic() < deadline:
            found = _executions_with_marker(marker)
            assert found == [], (
                "execution started despite the target role's trust policy omitting "
                f"events.amazonaws.com: {found}"
            )
            time.sleep(interval_s)

    _assert_never_starts_within(marker1, window_s=20.0)

    # Fix: correct the trust policy so events.amazonaws.com CAN assume the role.
    iam.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }],
        }),
    )

    marker2 = ctx.unique_name("negtrust-fixed-")

    def _send_and_check():
        events.put_events(Entries=[{
            "Source": "custom.negtrust",
            "DetailType": "NegTrustTest",
            "Detail": json.dumps({"marker": marker2}),
        }])
        return _executions_with_marker(marker2)

    found = _poll_until(
        _send_and_check,
        lambda f: len(f) > 0,
        timeout_s=90,
        interval_s=5.0,
        description="positive control: execution starts once trust policy is fixed",
    )
    exec_arn = found[0]["executionArn"]
    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60,
        interval_s=2.0,
        description="positive control execution reached a terminal state",
    )
    assert final["status"] == "SUCCEEDED", (
        f"positive-control execution did not succeed after the trust policy was corrected: {final}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
