"""cfn-state-machine-tags-value-change-and-key-removal-update-complete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-state-machine-tags-value-change-and-key-removal-update-complete"
GROUP = "deploy"
SERVICES = ["cloudformation", "stepfunctions"]

_DEFINITION = {"StartAt": "Hold", "States": {"Hold": {"Type": "Pass", "End": True}}}

_STACK_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
})


def _template(sm_name: str, tag_entries: list[dict]) -> str:
    """One IAM role plus one AWS::StepFunctions::StateMachine tagged with ``tag_entries``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "MyStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineName": sm_name,
                    "DefinitionString": json.dumps(_DEFINITION),
                    "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Tags": tag_entries,
                },
            },
        },
    })


def _stack_status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _poll_stack_terminal(cfn, stack_id: str, *, timeout_s: float = 300.0, interval_s: float = 3.0) -> str:
    """Poll DescribeStacks(StackId) until StackStatus lands in a terminal value; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = _stack_status(cfn, stack_id)
        if status in _STACK_TERMINAL:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(interval_s)


def _delete_stack_if_present(cfn, stack_id: str) -> None:
    """DeleteStack and wait for DELETE_COMPLETE; a no-op if it is already gone. Safe to call twice."""
    try:
        status = _stack_status(cfn, stack_id)
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ValidationError":
            return
        raise
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    ended = _poll_stack_terminal(cfn, stack_id, timeout_s=300.0)
    if ended != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {ended!r}, expected DELETE_COMPLETE")


def _user_tags(sfn, arn: str) -> dict:
    """The resource's own tag set, with CloudFormation's own ``aws:cloudformation:*`` tags excluded."""
    return {
        t["key"]: t["value"] for t in sfn.list_tags_for_resource(resourceArn=arn)["tags"]
        if not t["key"].startswith("aws:cloudformation:")
    }


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An update that changes one state machine tag's value and drops another completes,
    keeps the ARN and creation date, and leaves exactly the new tag set (besides the
    aws:cloudformation:* tags)."""
    cfn, sfn = ctx.client("cloudformation"), ctx.client("stepfunctions")
    stack_name = ctx.unique_name("sim2real-behav-sfntagsstack-")
    sm_name = ctx.unique_name("sim2real-behav-sfntagssm-")

    before_tags = [
        {"Key": "alpha", "Value": "first"},
        {"Key": "beta", "Value": "keep"},
        {"Key": "gamma", "Value": "drop-me"},
    ]
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(sm_name, before_tags),
        Capabilities=["CAPABILITY_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_if_present(cfn, stack_id))

    status = _poll_stack_terminal(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack create ended {status!r}, expected CREATE_COMPLETE"

    partition = stack_id.split(":")[1]
    arn = f"arn:{partition}:states:{ctx.region}:{ctx.account}:stateMachine:{sm_name}"

    before = sfn.describe_state_machine(stateMachineArn=arn)
    assert before["stateMachineArn"] == arn, (
        f"expected stateMachineArn {arn!r}, got {before['stateMachineArn']!r}"
    )
    before_user_tags = _user_tags(sfn, arn)
    assert before_user_tags == {"alpha": "first", "beta": "keep", "gamma": "drop-me"}, (
        f"expected the three tags the template declared, got {before_user_tags!r}"
    )

    after_tags = [
        {"Key": "alpha", "Value": "second"},
        {"Key": "beta", "Value": "keep"},
    ]
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(sm_name, after_tags),
        Capabilities=["CAPABILITY_IAM"],
    )
    status = _poll_stack_terminal(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack update ended {status!r}, expected UPDATE_COMPLETE"

    after = sfn.describe_state_machine(stateMachineArn=arn)
    got = (after["stateMachineArn"], after["creationDate"])
    expected = (arn, before["creationDate"])
    assert got == expected, (
        f"expected the same ARN and creation date {expected!r} (no replacement), got {got!r}"
    )

    after_user_tags = _user_tags(sfn, arn)
    assert after_user_tags == {"alpha": "second", "beta": "keep"}, (
        f"expected alpha's new value with gamma gone, got {after_user_tags!r}"
    )

    _delete_stack_if_present(cfn, stack_id)
    try:
        gone = sfn.describe_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        err = exc.response["Error"]
        got_err = (err.get("Code"), err.get("Message"))
        expected_err = ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{arn}'")
        assert got_err == expected_err, f"expected {expected_err!r}, got {got_err!r}"
    else:
        raise AssertionError(f"expected the deleted state machine to be unreadable, got {gone!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
