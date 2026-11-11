"""logs-loggroup-handler-permission-update-denied-then-delete-denied-recovers."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "logs-loggroup-handler-permission-update-denied-then-delete-denied-recovers"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "logs"]

# The AWS::Logs::LogGroup resource type's declared create+update+delete handler permissions
# (CloudFormation registry schema, us-west-2), deduplicated.
_FULL_PERMISSIONS = [
    "logs:DescribeLogGroups",
    "logs:CreateLogGroup",
    "logs:PutRetentionPolicy",
    "logs:TagResource",
    "logs:GetDataProtectionPolicy",
    "logs:PutDataProtectionPolicy",
    "logs:CreateLogDelivery",
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
_MISSING_UPDATE_ACTION = "logs:PutRetentionPolicy"
_MISSING_DELETE_ACTION = "logs:DeleteLogGroup"
_ROLE_BUDGET_S = 90.0

_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ATTEMPT_RE = re.compile(r"SDK Attempt Count: \d+")
_SESSION_RE = re.compile(r"(assumed-role/[^/]+/)[\w+=,.@-]+")


def _mask(message: str) -> str:
    """Replace the per-call request ids, attempt count and session suffix with placeholders."""
    message = _ID_RE.sub("<id>", message)
    message = _ATTEMPT_RE.sub("SDK Attempt Count: <n>", message)
    message = _SESSION_RE.sub(r"\1<session>", message)
    return message


def _is_subsequence(expected: list, actual: list) -> bool:
    it = iter(actual)
    return all(item in it for item in expected)


@tags(
    "axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A role missing AWS::Logs::LogGroup's UPDATE handler permission fails a retention update
    and rolls the group back unset; one missing its DELETE permission fails delete the same way,
    and a role holding it then deletes for real.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    full_role = _make_role(ctx, iam, _FULL_PERMISSIONS)
    update_role = _make_role(ctx, iam, [a for a in _FULL_PERMISSIONS if a != _MISSING_UPDATE_ACTION])
    delete_role = _make_role(ctx, iam, [a for a in _FULL_PERMISSIONS if a != _MISSING_DELETE_ACTION])

    # Positive control: the full permission set creates, sets retention in place, then deletes.
    pos_stack = ctx.unique_name("sim2real-xsvc-logsud-")
    pos_group = "/" + ctx.unique_name("sim2real-xsvc-logsud-")
    _create_stack_with_role(ctx, cfn, pos_stack, _template(pos_group, None), full_role["arn"])
    ctx.on_cleanup(_stack_teardown(cfn, pos_stack, full_role["arn"]))
    status = _wait_stack_terminal(cfn, pos_stack)
    assert status == "CREATE_COMPLETE", (
        f"the exactly-permissioned role's create ended {status!r}: {_failed_events(cfn, pos_stack)!r}"
    )
    pos_found = _exact_group(logs, pos_group)
    assert pos_found is not None, f"log group {pos_group} is not visible after CREATE_COMPLETE"
    pos_created_at = pos_found["creationTime"]

    cfn.update_stack(StackName=pos_stack, TemplateBody=_template(pos_group, 1), RoleARN=full_role["arn"])
    status = _wait_stack_terminal(
        cfn, pos_stack, terminal={"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"}
    )
    assert status == "UPDATE_COMPLETE", (
        f"the exactly-permissioned role's update ended {status!r}: {_failed_events(cfn, pos_stack)!r}"
    )
    pos_updated = _exact_group(logs, pos_group)
    assert pos_updated is not None, f"log group {pos_group} is not visible after UPDATE_COMPLETE"
    assert pos_updated["creationTime"] == pos_created_at, (
        "the log group's creationTime changed on update: it was replaced, not updated in place"
    )
    assert pos_updated.get("retentionInDays") == 1, (
        f"log group retentionInDays after the permitted update is {pos_updated.get('retentionInDays')!r}"
    )

    cfn.delete_stack(StackName=pos_stack, RoleARN=full_role["arn"])
    status = _wait_stack_terminal(cfn, pos_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"the exactly-permissioned role's delete ended {status!r}"
    assert _exact_group(logs, pos_group) is None, f"log group {pos_group} survived stack delete"

    # (a) UPDATE denial: the role minus logs:PutRetentionPolicy creates cleanly (retention stays
    # unset, so create never calls PutRetentionPolicy) but fails setting retention; the stack
    # rolls back and the group keeps its never-replaced, retention-unset state.
    upd_stack = ctx.unique_name("sim2real-xsvc-logsud-")
    upd_group = "/" + ctx.unique_name("sim2real-xsvc-logsud-")
    _create_stack_with_role(ctx, cfn, upd_stack, _template(upd_group, None), update_role["arn"])
    ctx.on_cleanup(_stack_teardown(cfn, upd_stack, update_role["arn"]))
    status = _wait_stack_terminal(cfn, upd_stack)
    assert status == "CREATE_COMPLETE", f"the update-denied role's create ended {status!r}"
    upd_before = _exact_group(logs, upd_group)
    assert upd_before is not None, f"log group {upd_group} is not visible after CREATE_COMPLETE"
    upd_created_at = upd_before["creationTime"]

    cfn.update_stack(StackName=upd_stack, TemplateBody=_template(upd_group, 1), RoleARN=update_role["arn"])
    status = _wait_stack_terminal(
        cfn,
        upd_stack,
        terminal={"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"},
    )
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"the role missing logs:PutRetentionPolicy produced {status!r}: {_failed_events(cfn, upd_stack)!r}"
    )

    upd_events = _events(cfn, upd_stack)
    decisive = [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in upd_events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
    ]
    expected_subsequence = [
        ("Group", "UPDATE_FAILED"),
        (upd_stack, "UPDATE_ROLLBACK_COMPLETE"),
    ]
    assert _is_subsequence(expected_subsequence, decisive), (
        f"decisive events were {decisive!r}, expected the subsequence {expected_subsequence!r}"
    )

    reason = next(
        e.get("ResourceStatusReason") or ""
        for e in upd_events
        if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Group", "UPDATE_FAILED")
    )
    expected_reason = (
        'Resource handler returned message: "User: '
        f"arn:aws:sts::{ctx.account}:assumed-role/{update_role['name']}/<session> "
        "is not authorized to perform: logs:PutRetentionPolicy on resource: "
        f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{upd_group} "
        "because no identity-based policy allows the logs:PutRetentionPolicy action "
        '(Service: CloudWatchLogs, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)" '
        "(RequestToken: <id>, HandlerErrorCode: AccessDenied)"
    )
    assert _mask(reason) == expected_reason, f"the log group update failed with {reason!r}"

    upd_after = _exact_group(logs, upd_group)
    assert upd_after is not None, f"log group {upd_group} is not visible after the rolled-back update"
    assert upd_after["creationTime"] == upd_created_at, (
        "the log group's creationTime changed on the rolled-back update: it was replaced"
    )
    assert "retentionInDays" not in upd_after, (
        f"log group retention after the rolled-back update is {upd_after.get('retentionInDays')!r}"
    )

    # (b) DELETE denial: the role minus logs:DeleteLogGroup fails delete; recovering with a role
    # that holds the permission actually removes the group.
    del_stack = ctx.unique_name("sim2real-xsvc-logsud-")
    del_group = "/" + ctx.unique_name("sim2real-xsvc-logsud-")
    _create_stack_with_role(ctx, cfn, del_stack, _template(del_group, None), delete_role["arn"])
    ctx.on_cleanup(_stack_teardown(cfn, del_stack, full_role["arn"]))
    status = _wait_stack_terminal(cfn, del_stack)
    assert status == "CREATE_COMPLETE", f"the delete-denied role's create ended {status!r}"
    assert _exact_group(logs, del_group) is not None, f"log group {del_group} is not visible after create"

    cfn.delete_stack(StackName=del_stack, RoleARN=delete_role["arn"])
    status = _wait_stack_terminal(cfn, del_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_FAILED", f"the role missing logs:DeleteLogGroup produced {status!r}"

    del_events = _events(cfn, del_stack)
    del_decisive = [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in del_events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
    ]
    expected_del_subsequence = [("Group", "DELETE_FAILED"), (del_stack, "DELETE_FAILED")]
    assert _is_subsequence(expected_del_subsequence, del_decisive), (
        f"decisive events were {del_decisive!r}, expected the subsequence {expected_del_subsequence!r}"
    )
    del_reason = next(
        e.get("ResourceStatusReason") or ""
        for e in del_events
        if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Group", "DELETE_FAILED")
    )
    expected_del_reason = (
        'Resource handler returned message: "User: '
        f"arn:aws:sts::{ctx.account}:assumed-role/{delete_role['name']}/<session> "
        "is not authorized to perform: logs:DeleteLogGroup on resource: "
        f"arn:aws:logs:{ctx.region}:{ctx.account}:log-group:{del_group} "
        "because no identity-based policy allows the logs:DeleteLogGroup action "
        '(Service: CloudWatchLogs, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)" '
        "(RequestToken: <id>, HandlerErrorCode: InvalidRequest)"
    )
    assert _mask(del_reason) == expected_del_reason, f"the log group delete failed with {del_reason!r}"
    assert _exact_group(logs, del_group) is not None, "the log group denied deletion is gone"

    cfn.delete_stack(StackName=del_stack, RoleARN=full_role["arn"])
    status = _wait_stack_terminal(cfn, del_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"the recovered delete ended {status!r}"
    assert _exact_group(logs, del_group) is None, f"log group {del_group} survived the recovered delete"


def _exact_group(logs, name: str) -> dict | None:
    """The one log group whose name is exactly ``name`` (prefix listing, paginated)."""
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page.get("logGroups", []):
            if g["logGroupName"] == name:
                return g
    return None


def _template(group_name: str, retention_days: int | None) -> str:
    props: dict = {"LogGroupName": group_name}
    if retention_days is not None:
        props["RetentionInDays"] = retention_days
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Group": {"Type": "AWS::Logs::LogGroup", "Properties": props}},
        }
    )


def _make_role(ctx, iam, actions: list[str]) -> dict:
    name = ctx.unique_name("sim2real-xsvc-logsud-")
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
