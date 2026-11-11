"""change-set-role-arn-is-the-acting-principal."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-role-arn-is-the-acting-principal"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "sqs", "ssm"]

_ASSUME_BUDGET_S = 90.0


@tags("axis:happy-path", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A change set's RoleARN is the principal that provisions: a role allowed only ssm:* fails the
    queue with an authorization error naming the role, an unrestricted role creates both, and
    DescribeStacks echoes each role.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    ssm = ctx.client("ssm")
    arms = {}
    for label, actions in (("narrow", ["ssm:*"]), ("wide", ["*"])):
        role = ctx.unique_name(f"sim2real-cfn-exec-{label}-")
        arn = iam.create_role(RoleName=role, AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
                           "Action": "sts:AssumeRole"}]}),
            Tags=[{"Key": "sim2real", "Value": CHECK}])["Role"]["Arn"]
        ctx.on_cleanup(_teardown(lambda r=role: iam.delete_role(RoleName=r), "NoSuchEntity"))
        iam.put_role_policy(RoleName=role, PolicyName="exec", PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}))
        ctx.on_cleanup(_teardown(
            lambda r=role: iam.delete_role_policy(RoleName=r, PolicyName="exec"), "NoSuchEntity"))
        arms[label] = {"role": role, "arn": arn,
                       "stack": ctx.unique_name(f"sim2real-cfn-exec-{label}-"),
                       "queue": ctx.unique_name(f"sim2real-cfn-exec-{label}-"),
                       "param": "/" + ctx.unique_name(f"sim2real-cfn-exec-{label}-")}

    for arm in arms.values():
        ctx.on_cleanup(_teardown(lambda a=arm: ssm.delete_parameter(Name=a["param"]),
                                 "ParameterNotFound"))
        ctx.on_cleanup(_teardown(lambda a=arm: _delete_queue(sqs, a["queue"]),
                                 "AWS.SimpleQueueService.NonExistentQueue"))
        ctx.on_cleanup(lambda a=arm: _delete_stack(cfn, a["stack"]))
        arm["id"] = _create_change_set(cfn, arm)

    for arm in arms.values():
        _wait_change_set(cfn, arm["id"])
        cfn.execute_change_set(StackName=arm["id"], ChangeSetName="deploy")

    narrow, wide = arms["narrow"], arms["wide"]
    stack = _settle(cfn, narrow["id"])
    assert (stack["StackStatus"], stack.get("RoleARN")) == ("ROLLBACK_COMPLETE", narrow["arn"]), (
        f"the ssm-only role's stack ended {stack['StackStatus']!r} with RoleARN "
        f"{stack.get('RoleARN')!r}"
    )
    events = _events(cfn, narrow["id"])
    assert ("Param", "CREATE_COMPLETE") in {(e["LogicalResourceId"], e["ResourceStatus"])
                                            for e in events}, "the permitted parameter was never created"
    failed = [e.get("ResourceStatusReason") or "" for e in events
              if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Queue", "CREATE_FAILED")]
    assert len(failed) == 1, f"expected one CREATE_FAILED event for the queue, got {failed!r}"
    pattern = (
        r'Resource handler returned message: "User: '
        + re.escape(f"arn:aws:sts::{ctx.account}:assumed-role/{narrow['role']}/")
        + r"[\w+=,.@-]+ is not authorized to perform: sqs:createqueue on resource: "
        + re.escape(f"arn:aws:sqs:{ctx.region}:{ctx.account}:{narrow['queue']}")
        + r" because no identity-based policy allows the sqs:createqueue action \(Service: Sqs, "
        r'Status Code: 403, Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)" '
        r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: AccessDenied\)"
    )
    assert re.fullmatch(pattern, failed[0]), f"the queue failed with {failed[0]!r}"
    gone = _err(lambda: sqs.get_queue_url(QueueName=narrow["queue"]))
    assert gone == ("AWS.SimpleQueueService.NonExistentQueue", "The specified queue does not exist."), (
        f"the queue the ssm-only role could not create answers {gone!r}"
    )
    gone = _err(lambda: ssm.get_parameter(Name=narrow["param"]))
    assert gone == ("ParameterNotFound", ""), f"the rolled-back parameter answers {gone!r}"

    stack = _settle(cfn, wide["id"])
    assert (stack["StackStatus"], stack.get("RoleARN")) == ("CREATE_COMPLETE", wide["arn"]), (
        f"the unrestricted role's stack ended {stack['StackStatus']!r} with RoleARN "
        f"{stack.get('RoleARN')!r} ({stack.get('StackStatusReason')!r})"
    )
    url = sqs.get_queue_url(QueueName=wide["queue"])["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    assert arn == f"arn:aws:sqs:{ctx.region}:{ctx.account}:{wide['queue']}", (
        f"the created queue's ARN is {arn!r}"
    )
    value = ssm.get_parameter(Name=wide["param"])["Parameter"]["Value"]
    assert value == "made-by-role", f"the created parameter holds {value!r}"


def _template(arm: dict) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Param": {"Type": "AWS::SSM::Parameter", "Properties": {
                "Name": arm["param"], "Type": "String", "Value": "made-by-role"}},
            "Queue": {"Type": "AWS::SQS::Queue", "DependsOn": "Param",
                      "Properties": {"QueueName": arm["queue"]}},
        },
    })


def _create_change_set(cfn, arm: dict) -> str:
    """CreateChangeSet with the role, retried while the new role is not yet assumable."""
    deadline = time.monotonic() + _ASSUME_BUDGET_S
    while True:
        try:
            return cfn.create_change_set(
                StackName=arm["stack"], ChangeSetName="deploy", ChangeSetType="CREATE",
                TemplateBody=_template(arm), RoleARN=arm["arn"])["StackId"]
        except ClientError as exc:
            message = exc.response["Error"].get("Message", "")
            # IAM propagation: CloudFormation cannot assume a role created seconds ago.
            if message != f"Role {arm['arn']} is invalid or cannot be assumed":
                raise
            if time.monotonic() > deadline:
                raise
        time.sleep(3.0)


def _wait_change_set(cfn, stack_id: str, *, timeout_s: float = 120.0) -> dict:
    """DescribeChangeSet once it is CREATE_COMPLETE; raises on FAILED or timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        described = cfn.describe_change_set(StackName=stack_id, ChangeSetName="deploy")
        if described["Status"] == "CREATE_COMPLETE":
            return described
        if described["Status"] == "FAILED" or time.monotonic() > deadline:
            raise AssertionError(
                f"change set is {described['Status']!r}: {described.get('StatusReason')!r}"
            )
        time.sleep(2.0)


def _settle(cfn, stack_id: str, *, timeout_s: float = 300.0) -> dict:
    """The stack once no operation is in progress on it; raises on timeout."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3.0)


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
    return [e for page in pages for e in page["StackEvents"]][::-1]


def _err(fn) -> tuple[str, str]:
    """The (code, message) a call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_queue(sqs, name: str) -> None:
    sqs.delete_queue(QueueUrl=sqs.get_queue_url(QueueName=name)["QueueUrl"])


def _delete_stack(cfn, name: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by id and wait for DELETE_COMPLETE; a stack never created is a no-op."""
    try:
        stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    stack_id = stack["StackId"]
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" or time.monotonic() > deadline:
            raise AssertionError(f"stack {name} teardown ended {status!r}")
        time.sleep(5.0)


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
