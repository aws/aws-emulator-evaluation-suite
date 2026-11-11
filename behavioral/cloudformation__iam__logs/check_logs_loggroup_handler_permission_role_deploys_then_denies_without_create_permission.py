"""logs-loggroup-handler-permission-role-deploys-then-denies-without-create-permission."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-loggroup-handler-permission-role-deploys-then-denies-without-create-permission"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "logs"]

# The AWS::Logs::LogGroup resource type's declared create+update+delete handler permissions
# (CloudFormation registry schema), deduplicated.
_FULL_PERMISSIONS = [
    "logs:DescribeLogGroups",
    "logs:CreateLogGroup",
    "logs:PutRetentionPolicy",
    "logs:TagResource",
    "logs:GetDataProtectionPolicy",
    "logs:PutDataProtectionPolicy",
    "logs:CreateLogDelivery",
    # Verbatim from the resource schema's handler permissions, though it names no IAM action.
    "s3:REST.PUT.OBJECT",
    "firehose:TagDeliveryStream",
    "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies",
    "logs:PutIndexPolicy",
    "logs:DescribeIndexPolicies",
    "logs:PutBearerTokenAuthentication",
    "logs:AssociateKmsKey",
    "logs:DisassociateKmsKey",
    "logs:DeleteRetentionPolicy",
    "logs:UntagResource",
    "logs:ListTagsForResource",
    "logs:DeleteIndexPolicy",
    "logs:DeleteResourcePolicy",
    "logs:PutLogGroupDeletionProtection",
    "logs:DeleteLogGroup",
    "logs:DeleteDataProtectionPolicy",
]
_MISSING_ACTION = "logs:CreateLogGroup"
_ROLE_BUDGET_S = 90.0


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation service role granted exactly AWS::Logs::LogGroup's declared handler
    permissions deploys and deletes a log group; the same role minus logs:CreateLogGroup fails
    the group with the exact AccessDenied status reason naming that action.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    positive_role = _make_role(ctx, iam, _FULL_PERMISSIONS)
    negative_role = _make_role(ctx, iam, [a for a in _FULL_PERMISSIONS if a != _MISSING_ACTION])

    # Positive control: exactly the declared permissions create and delete a real log group.
    pos_stack = ctx.unique_name("sim2real-xsvc-logshp-")
    pos_group = "/" + ctx.unique_name("sim2real-xsvc-logshp-")
    status = _create_positive_stack(ctx, cfn, pos_stack, _template(pos_group), positive_role["arn"])
    assert status == "CREATE_COMPLETE", (
        f"the exactly-permissioned role's stack ended {status!r}: "
        f"{_failed_events(cfn, pos_stack)!r}"
    )
    found = _exact_group(logs, pos_group)
    assert found is not None, f"log group {pos_group} is not visible after CREATE_COMPLETE"

    cfn.delete_stack(StackName=pos_stack, RoleARN=positive_role["arn"])
    delete_status = _wait_stack_terminal(cfn, pos_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert delete_status == "DELETE_COMPLETE", f"stack delete ended {delete_status!r}"
    assert _exact_group(logs, pos_group) is None, f"log group {pos_group} survived stack delete"

    # Negative: the same permission set minus logs:CreateLogGroup fails CREATE on the one
    # action CloudFormation must call first; the group never exists.
    neg_stack = ctx.unique_name("sim2real-xsvc-logshp-")
    neg_group = "/" + ctx.unique_name("sim2real-xsvc-logshp-")
    _create_stack_with_role(
        ctx, cfn, neg_stack, _template(neg_group), negative_role["arn"], disable_rollback=True
    )
    ctx.on_cleanup(_stack_teardown(cfn, neg_stack, negative_role["arn"]))
    status = _wait_stack_terminal(cfn, neg_stack, terminal={"CREATE_FAILED", "CREATE_COMPLETE"})
    assert status == "CREATE_FAILED", f"the role missing logs:CreateLogGroup produced {status!r}"

    failed = [
        e.get("ResourceStatusReason") or ""
        for e in _events(cfn, neg_stack)
        if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Group", "CREATE_FAILED")
    ]
    assert len(failed) == 1, f"expected one CREATE_FAILED event for the log group, got {failed!r}"
    pattern = (
        r'Resource handler returned message: "User: '
        + re.escape(f"arn:aws:sts::{ctx.account}:assumed-role/{negative_role['name']}/")
        + r"[\w+=,.@-]+ is not authorized to perform: logs:CreateLogGroup on resource: "
        + re.escape(f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{neg_group}")
        + r" because no identity-based policy allows the logs:CreateLogGroup action \(Service: "
        r'CloudWatchLogs, Status Code: 400, Request ID: [0-9a-f-]{36}\) \(SDK Attempt Count: \d+\)" '
        r"\(RequestToken: [0-9a-f-]{36}, HandlerErrorCode: AccessDenied\)"
    )
    assert re.fullmatch(pattern, failed[0]), f"the log group failed with {failed[0]!r}"
    assert _exact_group(logs, neg_group) is None, f"log group {neg_group} exists despite the denial"


def _template(group_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Group": {
                    "Type": "AWS::Logs::LogGroup",
                    "Properties": {"LogGroupName": group_name},
                }
            },
        }
    )


def _exact_group(logs, name: str) -> dict | None:
    """The one log group whose name is exactly ``name`` (prefix listing, paginated)."""
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page.get("logGroups", []):
            if g["logGroupName"] == name:
                return g
    return None


def _make_role(ctx, iam, actions: list[str]) -> dict:
    name = ctx.unique_name("sim2real-xsvc-logshp-")
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
