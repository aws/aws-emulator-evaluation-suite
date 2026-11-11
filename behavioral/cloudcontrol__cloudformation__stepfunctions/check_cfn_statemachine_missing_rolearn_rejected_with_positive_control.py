"""cfn-statemachine-missing-rolearn-rejected-with-positive-control."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-statemachine-missing-rolearn-rejected-with-positive-control"
GROUP = "deploy"
SERVICES = ["cloudcontrol", "cloudformation", "stepfunctions"]

_DEFINITION = {"StartAt": "S", "States": {"S": {"Type": "Pass", "End": True}}}
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}
# The handler reports a per-attempt RequestToken that is minted by AWS and unknowable in advance;
# the surrounding text is the only part a check can pin down.
_REASON_RE = re.compile(
    r'^Resource handler returned message: "Model validation failed '
    r'\(#: required key \[RoleArn\] not found\)" '
    r"\(RequestToken: ([0-9a-f-]{36}), HandlerErrorCode: InvalidRequest\)$"
)


def _poll(cf, stack_id: str, terminal: set, *, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _failure_reason(cf, stack_id: str, logical_id: str) -> str:
    """Reason of the CREATE_FAILED row of one logical resource."""
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if (event["ResourceStatus"] == "CREATE_FAILED"
                    and event["LogicalResourceId"] == logical_id
                    and event.get("ResourceStatusReason")):
                return event["ResourceStatusReason"]
    raise AssertionError(f"no CREATE_FAILED event for {logical_id!r} carrying a reason in {stack_id!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN AWS::StepFunctions::StateMachine missing the required RoleArn fails with the handler's
    model-validation reason and creates no state machine, while the same template with a RoleArn
    deploys with that role and definition, as Step Functions and Cloud Control both report.
    """
    cf = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")
    cc = ctx.client("cloudcontrol")

    bad_sm_name = ctx.unique_name("sim2real-behav-sfnnegsm-")
    bad_stack = ctx.unique_name("sim2real-behav-sfnnegstack-")
    bad_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SM": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": bad_sm_name,
                        "DefinitionString": json.dumps(_DEFINITION),
                    },
                },
            },
        }
    )
    bad_stack_id = cf.create_stack(
        StackName=bad_stack, TemplateBody=bad_template,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_stack_id))

    bad_status = _poll(cf, bad_stack_id, _CREATE_TERMINAL)
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"
    reason = _failure_reason(cf, bad_stack_id, "SM")
    match = _REASON_RE.match(reason)
    assert match is not None, (
        f"the missing-RoleArn failure reason no longer has the shape this check knows: {reason!r}"
    )
    expected_reason = (
        'Resource handler returned message: "Model validation failed '
        '(#: required key [RoleArn] not found)" '
        f"(RequestToken: {match.group(1)}, HandlerErrorCode: InvalidRequest)"
    )
    assert reason == expected_reason, f"expected {expected_reason!r}, got {reason!r}"

    bad_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name}"
    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_arn))
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code!r}"
    expected_message = f"State Machine Does Not Exist: '{bad_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the same shape, plus a real RoleArn, reaches CREATE_COMPLETE.
    role_name = ctx.unique_name("sim2real-behav-sfnctlrole-")
    good_sm_name = ctx.unique_name("sim2real-behav-sfnctlsm-")
    good_stack = ctx.unique_name("sim2real-behav-sfnctlstack-")
    good_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
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
                },
                "SM": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": good_sm_name,
                        "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "DefinitionString": json.dumps(_DEFINITION),
                    },
                },
            },
            "Outputs": {
                "SmArn": {"Value": {"Ref": "SM"}},
                "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
            },
        }
    )
    good_stack_id = cf.create_stack(
        StackName=good_stack, TemplateBody=good_template,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack_id))

    good_status = _poll(cf, good_stack_id, _CREATE_TERMINAL)
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cf.describe_stacks(StackName=good_stack_id)["Stacks"][0]["Outputs"]}
    good_arn = outputs["SmArn"]
    expected_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{good_sm_name}"
    assert good_arn == expected_arn, "Ref must be the state machine ARN of the declared name"
    role_arn = outputs["RoleArn"]
    assert role_arn == f"arn:aws:iam::{ctx.account}:role/{role_name}", (
        "Fn::GetAtt ExecRole.Arn must be the role ARN of the declared RoleName"
    )
    live = sfn.describe_state_machine(stateMachineArn=good_arn)
    assert live["name"] == good_sm_name, f"expected name {good_sm_name!r}, got {live['name']!r}"
    assert live["roleArn"] == role_arn, "Step Functions reports a roleArn other than the declared role"
    assert json.loads(live["definition"]) == _DEFINITION, (
        f"Step Functions reports definition {live['definition']!r}, expected {_DEFINITION!r}"
    )

    cc_props = json.loads(cc.get_resource(TypeName="AWS::StepFunctions::StateMachine", Identifier=good_arn)[
        "ResourceDescription"]["Properties"])
    got_cc = (cc_props.get("Arn") == good_arn, cc_props.get("RoleArn") == role_arn,
              cc_props.get("StateMachineName"))
    assert got_cc == (True, True, good_sm_name), (
        f"Cloud Control's model (Arn matches, RoleArn matches, StateMachineName) expected "
        f"(True, True, {good_sm_name!r}), got {got_cc!r}"
    )


def _delete_stack(cf, stack_id: str) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _poll(cf, stack_id, _DELETE_TERMINAL)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} ended {status!r}, expected DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
