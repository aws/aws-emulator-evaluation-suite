"""cfn-statemachine-tracingconfiguration-unknown-property-rejected-then-round-trips-enabled."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-statemachine-tracingconfiguration-unknown-property-rejected-then-round-trips-enabled"
GROUP = "deploy"
SERVICES = ["cloudformation", "stepfunctions"]

_DEFINITION = {"StartAt": "S", "States": {"S": {"Type": "Pass", "End": True}}}
_CREATE_TERMINAL = frozenset(
    {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
)
_DELETE_TERMINAL = frozenset({"DELETE_COMPLETE", "DELETE_FAILED"})
# The handler reports a per-attempt RequestToken that is minted by AWS and unknowable in advance;
# the surrounding text is the only part a check can pin down.
_REASON_RE = re.compile(
    r'^Resource handler returned message: "Model validation failed '
    r"\(#: extraneous key \[Bogus\] is not permitted\)\" "
    r"\(RequestToken: ([0-9a-f-]{36}), HandlerErrorCode: InvalidRequest\)$"
)


def _poll(cf, stack_id: str, terminal: frozenset, *, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _delete_stack(cf, stack_id: str) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _poll(cf, stack_id, _DELETE_TERMINAL, timeout_s=300.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} delete ended {status!r}")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _failure_reason(cf, stack_id: str, logical_id: str) -> str:
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if (
                event["ResourceStatus"] == "CREATE_FAILED"
                and event["LogicalResourceId"] == logical_id
                and event.get("ResourceStatusReason")
            ):
                return event["ResourceStatusReason"]
    raise AssertionError(
        f"no CREATE_FAILED event for {logical_id!r} carrying a reason in {stack_id!r}"
    )


def _trust_role(role_name: str) -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "RoleName": role_name,
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
        },
    }


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:deploy",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::StepFunctions::StateMachine TracingConfiguration with an unknown key fails the
    handler's model validation and creates no state machine; the same template with a plain
    TracingConfiguration.Enabled deploys, and DescribeStateMachine reports it exactly."""
    cf = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")

    # The one thing broken: an extraneous key inside TracingConfiguration.
    bad_role_name = ctx.unique_name("sim2real-behav-sfntracerole-bad-")
    bad_sm_name = ctx.unique_name("sim2real-behav-sfntracesm-bad-")
    bad_stack_name = ctx.unique_name("sim2real-behav-sfntracebad-stack-")
    bad_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": _trust_role(bad_role_name),
                "SM": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": bad_sm_name,
                        "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "DefinitionString": json.dumps(_DEFINITION),
                        "TracingConfiguration": {"Enabled": True, "Bogus": "x"},
                    },
                },
            },
        }
    )
    bad_stack_id = cf.create_stack(
        StackName=bad_stack_name,
        TemplateBody=bad_template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_stack_id))
    bad_status = _poll(cf, bad_stack_id, _CREATE_TERMINAL)
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"
    reason = _failure_reason(cf, bad_stack_id, "SM")
    match = _REASON_RE.match(reason)
    assert match is not None, (
        f"the extraneous-key failure reason no longer has the shape this check knows: {reason!r}"
    )
    expected_reason = (
        'Resource handler returned message: "Model validation failed '
        '(#: extraneous key [Bogus] is not permitted)" '
        f"(RequestToken: {match.group(1)}, HandlerErrorCode: InvalidRequest)"
    )
    assert reason == expected_reason, f"expected {expected_reason!r}, got {reason!r}"
    bad_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name}"
    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_arn))
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code!r}"
    assert message == f"State Machine Does Not Exist: '{bad_arn}'", (
        f"unexpected message {message!r}"
    )

    # Positive control: identical template, TracingConfiguration carrying only Enabled.
    good_role_name = ctx.unique_name("sim2real-behav-sfntracerole-good-")
    good_sm_name = ctx.unique_name("sim2real-behav-sfntracesm-good-")
    good_stack_name = ctx.unique_name("sim2real-behav-sfntracegood-stack-")
    good_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": _trust_role(good_role_name),
                "SM": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": good_sm_name,
                        "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "DefinitionString": json.dumps(_DEFINITION),
                        "TracingConfiguration": {"Enabled": True},
                    },
                },
            },
            "Outputs": {
                "StateMachineArn": {"Value": {"Ref": "SM"}},
            },
        }
    )
    good_stack_id = cf.create_stack(
        StackName=good_stack_name,
        TemplateBody=good_template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack_id))
    good_status = _poll(cf, good_stack_id, _CREATE_TERMINAL)
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cf.describe_stacks(StackName=good_stack_id)["Stacks"][0]["Outputs"]
    }
    good_arn = outputs["StateMachineArn"]
    desc = sfn.describe_state_machine(stateMachineArn=good_arn)
    assert desc["tracingConfiguration"] == {"enabled": True}, (
        f"expected tracingConfiguration {{'enabled': True}}, got {desc['tracingConfiguration']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
