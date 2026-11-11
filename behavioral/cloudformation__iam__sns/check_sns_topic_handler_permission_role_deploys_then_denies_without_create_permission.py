"""sns-topic-handler-permission-role-deploys-then-denies-without-create-permission."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sns-topic-handler-permission-role-deploys-then-denies-without-create-permission"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "sns"]

# The AWS::SNS::Topic resource type's declared create+update+delete handler permissions
# (CloudFormation registry schema), deduplicated.
_FULL_PERMISSIONS = [
    "sns:CreateTopic",
    "sns:TagResource",
    "sns:Subscribe",
    "sns:GetTopicAttributes",
    "sns:PutDataProtectionPolicy",
    "iam:GetRole",
    "iam:PassRole",
    "sns:SetTopicAttributes",
    "sns:UntagResource",
    "sns:Unsubscribe",
    "sns:ListTagsForResource",
    "sns:ListSubscriptionsByTopic",
    "sns:GetDataProtectionPolicy",
    "sns:DeleteTopic",
]
_MISSING_ACTION = "sns:CreateTopic"
_ROLE_BUDGET_S = 90.0


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation service role granted exactly AWS::SNS::Topic's declared handler
    permissions deploys and deletes a topic; the same role minus sns:CreateTopic fails the
    topic with the exact AccessDenied status reason naming that action.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sns = ctx.client("sns")

    positive_role = _make_role(ctx, iam, _FULL_PERMISSIONS)
    negative_role = _make_role(ctx, iam, [a for a in _FULL_PERMISSIONS if a != _MISSING_ACTION])

    # Positive control: exactly the declared permissions create and delete a real topic.
    pos_stack = ctx.unique_name("sim2real-xsvc-snshp-")
    pos_topic = ctx.unique_name("sim2real-xsvc-snshp-")
    status = _create_positive_stack(ctx, cfn, pos_stack, _template(pos_topic), positive_role["arn"])
    assert status == "CREATE_COMPLETE", (
        f"the exactly-permissioned role's stack ended {status!r}: "
        f"{_failed_events(cfn, pos_stack)!r}"
    )
    pos_topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{pos_topic}"
    topic_attrs = sns.get_topic_attributes(TopicArn=pos_topic_arn)["Attributes"]
    assert topic_attrs["TopicArn"] == pos_topic_arn, f"created topic attributes: {topic_attrs!r}"

    cfn.delete_stack(StackName=pos_stack, RoleARN=positive_role["arn"])
    delete_status = _wait_stack_terminal(cfn, pos_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert delete_status == "DELETE_COMPLETE", f"stack delete ended {delete_status!r}"
    gone = _err(lambda: sns.get_topic_attributes(TopicArn=pos_topic_arn))
    assert gone == ("NotFound", "Topic does not exist"), f"the deleted topic answers {gone!r}"

    # Negative: the same permission set minus sns:CreateTopic fails CREATE on the one action
    # CloudFormation must call first; the topic never exists.
    neg_stack = ctx.unique_name("sim2real-xsvc-snshp-")
    neg_topic = ctx.unique_name("sim2real-xsvc-snshp-")
    _create_stack_with_role(
        ctx, cfn, neg_stack, _template(neg_topic), negative_role["arn"], disable_rollback=True
    )
    ctx.on_cleanup(_stack_teardown(cfn, neg_stack, negative_role["arn"]))
    status = _wait_stack_terminal(cfn, neg_stack, terminal={"CREATE_FAILED", "CREATE_COMPLETE"})
    assert status == "CREATE_FAILED", f"the role missing sns:CreateTopic produced {status!r}"

    failed = [
        e.get("ResourceStatusReason") or ""
        for e in _events(cfn, neg_stack)
        if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Topic", "CREATE_FAILED")
    ]
    assert len(failed) == 1, f"expected one CREATE_FAILED event for the topic, got {failed!r}"
    neg_topic_arn = f"arn:aws:sns:{ctx.region}:{ctx.account}:{neg_topic}"
    pattern = (
        r'Resource handler returned message: "User: '
        + re.escape(f"arn:aws:sts::{ctx.account}:assumed-role/{negative_role['name']}/")
        + r"[\w+=,.@-]+ is not authorized to perform: SNS:CreateTopic on resource: "
        + re.escape(neg_topic_arn)
        + r" because no identity-based policy allows the SNS:CreateTopic action \(Service: Sns, "
        r'Status Code: 403, Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)" '
        r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: AccessDenied\)"
    )
    assert re.fullmatch(pattern, failed[0]), f"the topic failed with {failed[0]!r}"
    gone = _err(lambda: sns.get_topic_attributes(TopicArn=neg_topic_arn))
    assert gone == ("NotFound", "Topic does not exist"), f"the never-created topic answers {gone!r}"


def _template(topic_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Topic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": topic_name},
                }
            },
        }
    )


def _make_role(ctx, iam, actions: list[str]) -> dict:
    name = ctx.unique_name("sim2real-xsvc-snshp-")
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
    # iam:PassRole is scoped to the role itself: the template passes no role to SNS.
    statements = [{"Effect": "Allow", "Action": [a for a in actions if a != "iam:PassRole"], "Resource": "*"}]
    if "iam:PassRole" in actions:
        statements.append({"Effect": "Allow", "Action": "iam:PassRole", "Resource": arn})
    iam.put_role_policy(
        RoleName=name,
        PolicyName="handler-permissions",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
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
