"""sqs-queue-handler-permission-role-deploys-then-denies-without-create-permission."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-queue-handler-permission-role-deploys-then-denies-without-create-permission"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "sqs"]

# The AWS::SQS::Queue resource type's declared create+update+delete handler permissions
# (CloudFormation registry schema), deduplicated.
_FULL_PERMISSIONS = [
    "sqs:CreateQueue",
    "sqs:GetQueueUrl",
    "sqs:GetQueueAttributes",
    "sqs:ListQueueTags",
    "sqs:TagQueue",
    "sqs:SetQueueAttributes",
    "sqs:UntagQueue",
    "sqs:DeleteQueue",
]
_MISSING_ACTION = "sqs:CreateQueue"
_ROLE_BUDGET_S = 90.0


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation service role granted exactly AWS::SQS::Queue's declared handler
    permissions deploys and deletes a queue; the same role minus sqs:CreateQueue fails the
    queue with the exact AccessDenied status reason naming that action.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    positive_role = _make_role(ctx, iam, _FULL_PERMISSIONS)
    negative_role = _make_role(ctx, iam, [a for a in _FULL_PERMISSIONS if a != _MISSING_ACTION])

    # Positive control: exactly the declared permissions create and delete a real queue.
    pos_stack = ctx.unique_name("sim2real-xsvc-sqshp-")
    pos_queue = ctx.unique_name("sim2real-xsvc-sqshp-")
    status = _create_positive_stack(ctx, cfn, pos_stack, _template(pos_queue), positive_role["arn"])
    assert status == "CREATE_COMPLETE", (
        f"the exactly-permissioned role's stack ended {status!r}: "
        f"{_failed_events(cfn, pos_stack)!r}"
    )
    attrs = sqs.get_queue_attributes(
        QueueUrl=sqs.get_queue_url(QueueName=pos_queue)["QueueUrl"], AttributeNames=["QueueArn"]
    )["Attributes"]
    assert attrs["QueueArn"] == f"arn:aws:sqs:{ctx.region}:{ctx.account}:{pos_queue}", (
        f"created queue ARN is {attrs['QueueArn']!r}"
    )

    cfn.delete_stack(StackName=pos_stack, RoleARN=positive_role["arn"])
    delete_status = _wait_stack_terminal(cfn, pos_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert delete_status == "DELETE_COMPLETE", f"stack delete ended {delete_status!r}"
    gone = _wait_queue_gone(sqs, pos_queue)
    assert gone == (
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
    ), f"the deleted queue answers {gone!r}"

    # Negative: the same permission set minus sqs:CreateQueue fails CREATE on the one action
    # CloudFormation must call first; the queue never exists.
    neg_stack = ctx.unique_name("sim2real-xsvc-sqshp-")
    neg_queue = ctx.unique_name("sim2real-xsvc-sqshp-")
    _create_stack_with_role(
        ctx, cfn, neg_stack, _template(neg_queue), negative_role["arn"], disable_rollback=True
    )
    ctx.on_cleanup(_stack_teardown(cfn, neg_stack, negative_role["arn"]))
    status = _wait_stack_terminal(cfn, neg_stack, terminal={"CREATE_FAILED", "CREATE_COMPLETE"})
    assert status == "CREATE_FAILED", f"the role missing sqs:CreateQueue produced {status!r}"

    failed = [
        e.get("ResourceStatusReason") or ""
        for e in _events(cfn, neg_stack)
        if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Queue", "CREATE_FAILED")
    ]
    assert len(failed) == 1, f"expected one CREATE_FAILED event for the queue, got {failed!r}"
    pattern = (
        r'Resource handler returned message: "User: '
        + re.escape(f"arn:aws:sts::{ctx.account}:assumed-role/{negative_role['name']}/")
        + r"[\w+=,.@-]+ is not authorized to perform: sqs:createqueue on resource: "
        + re.escape(f"arn:aws:sqs:{ctx.region}:{ctx.account}:{neg_queue}")
        + r" because no identity-based policy allows the sqs:createqueue action \(Service: Sqs, "
        r'Status Code: 403, Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)" '
        r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: AccessDenied\)"
    )
    assert re.fullmatch(pattern, failed[0]), f"the queue failed with {failed[0]!r}"
    gone = _err(lambda: sqs.get_queue_url(QueueName=neg_queue))
    assert gone == (
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
    ), f"the never-created queue answers {gone!r}"


def _template(queue_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": queue_name},
                }
            },
        }
    )


def _make_role(ctx, iam, actions: list[str]) -> dict:
    name = ctx.unique_name("sim2real-xsvc-sqshp-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="handler-permissions",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(
        _teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName="handler-permissions"), "NoSuchEntity")
    )
    return {"name": name, "arn": arn}


def _create_stack_with_role(
    ctx, cfn, stack_name: str, template: str, role_arn: str, *, disable_rollback: bool = False
) -> None:
    """CreateStack with ``role_arn``, retried while IAM has not yet propagated the new role."""
    deadline = time.monotonic() + _ROLE_BUDGET_S
    kwargs: dict = {
        "StackName": stack_name,
        "TemplateBody": template,
        "RoleARN": role_arn,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if disable_rollback:
        kwargs["DisableRollback"] = True
    while True:
        try:
            cfn.create_stack(**kwargs)
            return
        except ClientError as exc:
            message = exc.response["Error"].get("Message", "")
            if message != f"Role {role_arn} is invalid or cannot be assumed":
                raise
            if time.monotonic() > deadline:
                raise
        time.sleep(3.0)


def _create_positive_stack(ctx, cfn, stack_name: str, template: str, role_arn: str) -> str:
    """Create the stack with ``role_arn`` and return its terminal status. Until IAM propagates the
    role's new policy the resource fails AccessDenied, so that failed stack is deleted and retried."""
    teardown = _stack_teardown(cfn, stack_name, role_arn)
    deadline = time.monotonic() + _ROLE_BUDGET_S
    registered = False
    while True:
        _create_stack_with_role(ctx, cfn, stack_name, template, role_arn)
        if not registered:
            ctx.on_cleanup(teardown)
            registered = True
        status = _wait_stack_terminal(cfn, stack_name)
        if status == "CREATE_COMPLETE":
            return status
        denied = [
            reason
            for _, resource_status, reason in _failed_events(cfn, stack_name)
            if resource_status == "CREATE_FAILED" and "HandlerErrorCode: AccessDenied" in (reason or "")
        ]
        if not denied or time.monotonic() > deadline:
            return status
        teardown()
        time.sleep(5.0)


def _wait_stack_terminal(cfn, name: str, *, terminal: set[str] | None = None, timeout_s: float = 300.0) -> str:
    terminal = terminal or {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (
                "DELETE_COMPLETE" in terminal
                and exc.response["Error"].get("Message") == f"Stack with id {name} does not exist"
            ):
                return "DELETE_COMPLETE"
            raise
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {name} still {status!r} after {timeout_s}s")
        time.sleep(2.0)


def _events(cfn, stack_name: str) -> list[dict]:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
    return [e for page in pages for e in page["StackEvents"]][::-1]


def _failed_events(cfn, stack_name: str) -> list:
    return [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack_name)
        if e["ResourceStatus"].endswith("FAILED")
    ]


def _wait_queue_gone(sqs, queue_name: str, *, timeout_s: float = 60.0) -> tuple[str, str]:
    """GetQueueUrl's (code, message) once the queue is gone; SQS deletion may lag DELETE_COMPLETE."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sqs.get_queue_url(QueueName=queue_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue":
                return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"queue {queue_name!r} still resolves {timeout_s}s after its delete")
        time.sleep(2.0)



def _err(fn) -> tuple[str, str]:
    """The (code, message) a call raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _stack_teardown(cfn, name: str, role_arn: str, *, timeout_s: float = 300.0):
    """Delete the stack with ``role_arn`` and wait for DELETE_COMPLETE; raises on failure."""

    def run_undo() -> None:
        try:
            cfn.describe_stacks(StackName=name)
        except ClientError as exc:
            if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
                return
            raise
        cfn.delete_stack(StackName=name, RoleARN=role_arn)
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
                    return
                raise
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED" or time.monotonic() > deadline:
                raise RuntimeError(f"stack {name} teardown ended {status!r}")
            time.sleep(3.0)

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
