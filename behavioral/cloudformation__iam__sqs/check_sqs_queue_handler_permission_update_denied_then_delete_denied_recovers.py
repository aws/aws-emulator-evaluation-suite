"""sqs-queue-handler-permission-update-denied-then-delete-denied-recovers."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-queue-handler-permission-update-denied-then-delete-denied-recovers"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "sqs"]

# The AWS::SQS::Queue resource type's declared create+update+delete handler permissions
# (CloudFormation registry schema, us-west-2), deduplicated.
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
_MISSING_UPDATE_ACTION = "sqs:TagQueue"
_MISSING_DELETE_ACTION = "sqs:DeleteQueue"
_ROLE_BUDGET_S = 90.0

_ID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_ATTEMPT_RE = re.compile(r"SDK Attempt Count: \d+")
_SESSION_RE = re.compile(r"(assumed-role/[^/]+/)[\w+=,.@-]+")


def _mask(message: str, account: str) -> str:
    """Replace the account, per-call request ids, attempt count and session suffix with placeholders."""
    message = message.replace(account, "<account>")
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
    """A role missing AWS::SQS::Queue's declared UPDATE handler permission fails a tagging
    update with the exact AccessDenied reason and rolls the queue back untagged; a role missing
    its DELETE permission fails delete the same way, and a role holding it then deletes for real.
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")

    full_role = _make_role(ctx, iam, _FULL_PERMISSIONS)
    update_role = _make_role(ctx, iam, [a for a in _FULL_PERMISSIONS if a != _MISSING_UPDATE_ACTION])
    delete_role = _make_role(ctx, iam, [a for a in _FULL_PERMISSIONS if a != _MISSING_DELETE_ACTION])

    # Positive control: the full permission set creates, retags in place, then deletes.
    pos_stack = ctx.unique_name("sim2real-xsvc-sqsud-")
    pos_queue = ctx.unique_name("sim2real-xsvc-sqsud-")
    _create_stack_with_role(ctx, cfn, pos_stack, _template(pos_queue, None), full_role["arn"])
    ctx.on_cleanup(_stack_teardown(cfn, pos_stack, full_role["arn"]))
    status = _wait_stack_terminal(cfn, pos_stack)
    assert status == "CREATE_COMPLETE", (
        f"the exactly-permissioned role's create ended {status!r}: {_failed_events(cfn, pos_stack)!r}"
    )
    pos_url = sqs.get_queue_url(QueueName=pos_queue)["QueueUrl"]
    pos_created_at = _created_timestamp(sqs, pos_url)

    cfn.update_stack(StackName=pos_stack, TemplateBody=_template(pos_queue, "after"), RoleARN=full_role["arn"])
    status = _wait_stack_terminal(
        cfn, pos_stack, terminal={"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE"}
    )
    assert status == "UPDATE_COMPLETE", (
        f"the exactly-permissioned role's update ended {status!r}: {_failed_events(cfn, pos_stack)!r}"
    )
    assert _created_timestamp(sqs, pos_url) == pos_created_at, (
        "the queue's CreatedTimestamp changed on update: it was replaced, not updated in place"
    )
    pos_tags = sqs.list_queue_tags(QueueUrl=pos_url).get("Tags", {})
    assert pos_tags == {"stage": "after"}, f"queue tags after the permitted update are {pos_tags!r}"

    cfn.delete_stack(StackName=pos_stack, RoleARN=full_role["arn"])
    status = _wait_stack_terminal(cfn, pos_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"the exactly-permissioned role's delete ended {status!r}"
    gone = _wait_queue_gone(sqs, pos_queue)
    assert gone == (
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
    ), f"the deleted queue answers {gone!r}"

    # (a) UPDATE denial: the role minus sqs:TagQueue creates cleanly (no tag yet, so create
    # never calls TagQueue) but fails the tagging update; the stack rolls back and the queue
    # keeps its untagged, never-replaced state.
    upd_stack = ctx.unique_name("sim2real-xsvc-sqsud-")
    upd_queue = ctx.unique_name("sim2real-xsvc-sqsud-")
    _create_stack_with_role(ctx, cfn, upd_stack, _template(upd_queue, None), update_role["arn"])
    ctx.on_cleanup(_stack_teardown(cfn, upd_stack, update_role["arn"]))
    status = _wait_stack_terminal(cfn, upd_stack)
    assert status == "CREATE_COMPLETE", (
        f"the update-denied role's create ended {status!r}: {_failed_events(cfn, upd_stack)!r}"
    )
    upd_url = sqs.get_queue_url(QueueName=upd_queue)["QueueUrl"]
    upd_created_at = _created_timestamp(sqs, upd_url)

    cfn.update_stack(StackName=upd_stack, TemplateBody=_template(upd_queue, "after"), RoleARN=update_role["arn"])
    status = _wait_stack_terminal(
        cfn,
        upd_stack,
        terminal={"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED"},
    )
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"the role missing sqs:TagQueue produced {status!r}: {_failed_events(cfn, upd_stack)!r}"
    )

    upd_events = _events(cfn, upd_stack)
    decisive = [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in upd_events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
    ]
    # CloudFormation logs the rollback's own property restore on the resource as UPDATE_COMPLETE
    # (it is, from the resource's perspective, just another successful update); only the
    # stack-level event names the operation UPDATE_ROLLBACK_COMPLETE.
    expected_subsequence = [
        ("Queue", "UPDATE_FAILED"),
        ("Queue", "UPDATE_COMPLETE"),
        (upd_stack, "UPDATE_ROLLBACK_COMPLETE"),
    ]
    assert _is_subsequence(expected_subsequence, decisive), (
        f"decisive events were {decisive!r}, expected the subsequence {expected_subsequence!r}"
    )

    reason = next(
        e.get("ResourceStatusReason") or ""
        for e in upd_events
        if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Queue", "UPDATE_FAILED")
    )
    expected_reason = (
        'Resource handler returned message: "Encountered a permissions error performing a '
        "tagging operation, please add required tag permissions. See "
        "https://repost.aws/knowledge-center/cloudformation-tagging-permission-error for how "
        'to resolve. Resource handler returned message: "User: '
        f"arn:aws:sts::<account>:assumed-role/{update_role['name']}/<session> "
        "is not authorized to perform: sqs:tagqueue on resource: "
        f"arn:aws:sqs:{ctx.region}:<account>:{upd_queue} "
        "because no identity-based policy allows the sqs:tagqueue action "
        '(Service: Sqs, Status Code: 403, Request ID: <id>) (SDK Attempt Count: <n>)"" '
        "(RequestToken: <id>, HandlerErrorCode: UnauthorizedTaggingOperation)"
    )
    assert _mask(reason, ctx.account) == expected_reason, f"the queue update failed with {reason!r}"

    assert _created_timestamp(sqs, upd_url) == upd_created_at, (
        "the queue's CreatedTimestamp changed on the rolled-back update: it was replaced"
    )
    rolled_back_tags = sqs.list_queue_tags(QueueUrl=upd_url).get("Tags", {})
    assert rolled_back_tags == {}, f"queue tags after the rolled-back update are {rolled_back_tags!r}"

    # (b) DELETE denial: the role minus sqs:DeleteQueue fails delete; recovering with a role
    # that holds the permission actually removes the queue.
    del_stack = ctx.unique_name("sim2real-xsvc-sqsud-")
    del_queue = ctx.unique_name("sim2real-xsvc-sqsud-")
    _create_stack_with_role(ctx, cfn, del_stack, _template(del_queue, None), delete_role["arn"])
    ctx.on_cleanup(_stack_teardown(cfn, del_stack, full_role["arn"]))
    status = _wait_stack_terminal(cfn, del_stack)
    assert status == "CREATE_COMPLETE", f"the delete-denied role's create ended {status!r}"
    del_url = sqs.get_queue_url(QueueName=del_queue)["QueueUrl"]

    cfn.delete_stack(StackName=del_stack, RoleARN=delete_role["arn"])
    status = _wait_stack_terminal(cfn, del_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_FAILED", f"the role missing sqs:DeleteQueue produced {status!r}"

    del_events = _events(cfn, del_stack)
    del_decisive = [
        (e["LogicalResourceId"], e["ResourceStatus"])
        for e in del_events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
    ]
    expected_del_subsequence = [("Queue", "DELETE_FAILED"), (del_stack, "DELETE_FAILED")]
    assert _is_subsequence(expected_del_subsequence, del_decisive), (
        f"decisive events were {del_decisive!r}, expected the subsequence {expected_del_subsequence!r}"
    )
    del_reason = next(
        e.get("ResourceStatusReason") or ""
        for e in del_events
        if (e["LogicalResourceId"], e["ResourceStatus"]) == ("Queue", "DELETE_FAILED")
    )
    expected_del_reason = (
        'Resource handler returned message: "User: '
        f"arn:aws:sts::<account>:assumed-role/{delete_role['name']}/<session> "
        "is not authorized to perform: sqs:deletequeue on resource: "
        f"arn:aws:sqs:{ctx.region}:<account>:{del_queue} "
        "because no identity-based policy allows the sqs:deletequeue action "
        '(Service: Sqs, Status Code: 403, Request ID: <id>) (SDK Attempt Count: <n>)" '
        "(RequestToken: <id>, HandlerErrorCode: AccessDenied)"
    )
    assert _mask(del_reason, ctx.account) == expected_del_reason, f"the queue delete failed with {del_reason!r}"

    attrs = sqs.get_queue_attributes(QueueUrl=del_url, AttributeNames=["QueueArn"])["Attributes"]
    assert attrs["QueueArn"] == f"arn:aws:sqs:{ctx.region}:{ctx.account}:{del_queue}", (
        f"the queue denied deletion is gone: {attrs!r}"
    )

    cfn.delete_stack(StackName=del_stack, RoleARN=full_role["arn"])
    status = _wait_stack_terminal(cfn, del_stack, terminal={"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"the recovered delete ended {status!r}"
    recovered_gone = _wait_queue_gone(sqs, del_queue)
    assert recovered_gone == (
        "AWS.SimpleQueueService.NonExistentQueue",
        "The specified queue does not exist.",
    ), f"the recovered-delete queue answers {recovered_gone!r}"


def _created_timestamp(sqs, queue_url: str) -> str:
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["CreatedTimestamp"])["Attributes"][
        "CreatedTimestamp"
    ]


def _template(queue_name: str, tag_value: str | None) -> str:
    props: dict = {"QueueName": queue_name}
    if tag_value is not None:
        props["Tags"] = [{"Key": "stage", "Value": tag_value}]
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"Queue": {"Type": "AWS::SQS::Queue", "Properties": props}},
        }
    )


def _make_role(ctx, iam, actions: list[str]) -> dict:
    name = ctx.unique_name("sim2real-xsvc-sqsud-")
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
    """CreateStack with ``role_arn``, retried while IAM propagates the new role; no stack-level
    ``Tags``, so the tagging permission is exercised only on the UPDATE path.
    """
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
