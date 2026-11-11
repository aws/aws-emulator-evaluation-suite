"""start-message-move-task-requires-composite-source-and-destination-permissions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-message-move-task-requires-composite-source-and-destination-permissions"
GROUP = "overly-permissive"
SERVICES = ["iam", "sqs", "sts"]

_SESSION = "sim2real-behav-smmt"
_TOKEN_NOT_YET = ("InvalidClientTokenId", "The security token included in the request is invalid.")


def _pair(exc: ClientError) -> tuple[str | None, str | None]:
    err = exc.response.get("Error", {})
    return err.get("Code"), err.get("Message")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role granted only sqs:StartMessageMoveTask on a DLQ is denied, naming the next missing
    action; granting the full composite permission set on the source and destination queues
    lets the identical call complete with every message moved."""
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    dlq_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-smmt-dlq-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    # Wiring a RedrivePolicy at this ARN is what makes the DLQ a dead-letter queue --
    # StartMessageMoveTask otherwise rejects the source with InvalidParameterValue.
    src_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-smmt-src-"),
        Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 2})},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    dst_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-smmt-dst-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dst_url))
    dst_arn = sqs.get_queue_attributes(QueueUrl=dst_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    bodies = {f"move-{i}" for i in range(2)}
    for body in bodies:
        sqs.send_message(QueueUrl=dlq_url, MessageBody=body)

    role_name, role_arn = _create_role(ctx, account)
    caller = f"arn:aws:sts::{account}:assumed-role/{role_name}/{_SESSION}"
    _grant(ctx, role_name, [("sqs:StartMessageMoveTask", dlq_arn)])
    role_creds = _assume(ctx, role_arn)
    _wait_for_credentials_active(ctx, role_creds)
    role_sqs = ctx.client("sqs", creds=role_creds)

    # baseline: StartMessageMoveTask alone on the source is not enough; AWS evaluates the
    # composite permission set and denies on the first one still missing.
    _RECEIVE_DENIED = _denied(caller, "sqs:receivemessage", dlq_arn)
    expect_error(
        lambda: role_sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=dst_arn),
        *_RECEIVE_DENIED,
    )

    # effect absent: no task was started, and the source queue still holds both messages.
    tasks = sqs.list_message_move_tasks(SourceArn=dlq_arn).get("Results", [])
    assert tasks == [], f"expected no move tasks after the denied call, got {tasks!r}"
    _poll_queue_counters(sqs, dlq_url, {"ApproximateNumberOfMessages": "2"})

    # restore: the composite grant AWS actually requires -- Receive+Delete+GetAttributes on
    # the source, Send on the destination -- is what flips the identical call.
    _grant(
        ctx,
        role_name,
        [
            ("sqs:StartMessageMoveTask", dlq_arn),
            ("sqs:ReceiveMessage", dlq_arn),
            ("sqs:DeleteMessage", dlq_arn),
            ("sqs:GetQueueAttributes", dlq_arn),
            ("sqs:SendMessage", dst_arn),
        ],
    )
    # While the composite grant propagates, the call is denied on whichever action is not yet
    # live: exactly these refusals are retried.
    not_yet = {
        _denied(caller, action, resource)
        for action, resource in (
            ("sqs:startmessagemovetask", dlq_arn),
            ("sqs:receivemessage", dlq_arn),
            ("sqs:deletemessage", dlq_arn),
            ("sqs:getqueueattributes", dlq_arn),
            ("sqs:sendmessage", dst_arn),
        )
    }
    resp = _until_allowed(
        lambda: role_sqs.start_message_move_task(SourceArn=dlq_arn, DestinationArn=dst_arn),
        not_yet,
    )
    assert resp.get("TaskHandle"), f"the fully-granted call returned no TaskHandle: {resp!r}"

    task = _poll_task_terminal(sqs, dlq_arn, timeout_s=120.0)
    assert task.get("Status") == "COMPLETED", f"the move task ended as {task!r}, expected COMPLETED"
    assert task.get("ApproximateNumberOfMessagesMoved") == 2, (
        f"expected both messages moved, task reported {task!r}"
    )

    _poll_queue_counters(sqs, dst_url, {"ApproximateNumberOfMessages": "2"})
    moved_bodies = _receive_all_bodies(sqs, dst_url, len(bodies))
    assert moved_bodies == bodies, f"expected {bodies!r} on the destination, got {moved_bodies!r}"


def _denied(caller_arn, action, resource_arn):
    """The exact (code, message) real SQS returns for a principal with no identity grant."""
    return (
        "AccessDenied",
        f"User: {caller_arn} is not authorized to perform: {action} on resource: {resource_arn} "
        f"because no identity-based policy allows the {action} action",
    )


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = _pair(exc)
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _create_role(ctx, account):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-smmtrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_role(iam, name))
    return name, f"arn:aws:iam::{account}:role/{name}"


def _delete_role(iam, name):
    for policy_name in iam.list_role_policies(RoleName=name)["PolicyNames"]:
        iam.delete_role_policy(RoleName=name, PolicyName=policy_name)
    iam.delete_role(RoleName=name)


def _grant(ctx, role_name, action_resource_pairs):
    """Replace the role's one inline policy with an Allow statement per (action, resource) pair."""
    iam = ctx.client("iam")
    statements = [
        {"Effect": "Allow", "Action": action, "Resource": resource}
        for action, resource in action_resource_pairs
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-grant",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )


def _assume(ctx, role_arn):
    """Session credentials for ``role_arn``; AssumeRole retries only the exact denial a new
    role's trust answers while it propagates."""
    sts = ctx.client("sts")
    me = sts.get_caller_identity()["Arn"]
    not_yet = ("AccessDenied",
               f"User: {me} is not authorized to perform: sts:AssumeRole on resource: {role_arn}")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            c = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION)["Credentials"]
            break
        except ClientError as exc:
            if _pair(exc) != not_yet or time.monotonic() > deadline:
                raise
            time.sleep(3)
    return {
        "aws_access_key_id": c["AccessKeyId"],
        "aws_secret_access_key": c["SecretAccessKey"],
        "aws_session_token": c["SessionToken"],
    }


def _wait_for_credentials_active(ctx, creds, *, timeout_s=60.0, interval_s=3.0):
    """Block until the assumed session itself authenticates (distinct from its authorization),
    retrying only the exact refusal of a token STS has not yet propagated."""
    sts = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sts.get_caller_identity()
            return
        except ClientError as exc:
            if _pair(exc) != _TOKEN_NOT_YET or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


def _until_allowed(fn, not_yet, *, timeout_s=120.0, interval_s=3.0):
    """Call ``fn`` until it stops raising one of the exact ``not_yet`` denials, bounded."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if _pair(exc) not in not_yet or time.monotonic() > deadline:
                raise
        time.sleep(interval_s)


def _receive_all_bodies(sqs, queue_url, n, *, timeout_s=60.0):
    """The bodies of ``n`` messages, collected across as many ReceiveMessage calls as it takes."""
    bodies = set()
    deadline = time.monotonic() + timeout_s
    while len(bodies) < n and time.monotonic() < deadline:
        for m in sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        ).get("Messages", []):
            bodies.add(m["Body"])
    assert len(bodies) == n, f"received {len(bodies)} of {n} expected bodies within {timeout_s}s"
    return bodies


def _poll_queue_counters(sqs, queue_url, expected, timeout_s=90.0, interval_s=3.0):
    """Poll GetQueueAttributes until every named counter equals its expected string value."""
    deadline = time.monotonic() + timeout_s
    while True:
        attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=list(expected))["Attributes"]
        observed = {name: attrs.get(name) for name in expected}
        if observed == expected:
            return attrs
        if time.monotonic() >= deadline:
            raise AssertionError(f"queue counters never reached {expected}; last observed {observed}")
        time.sleep(interval_s)


def _poll_task_terminal(sqs, source_arn, *, timeout_s=120.0, interval_s=3.0):
    """Poll ListMessageMoveTasks for a terminal status whose moved counter has caught up to the
    total; a COMPLETED status can briefly precede its own counter settling."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        results = sqs.list_message_move_tasks(SourceArn=source_arn).get("Results", [])
        if results:
            last = results[0]
            status = last.get("Status")
            if status == "COMPLETED" and last.get("ApproximateNumberOfMessagesMoved") == last.get(
                "ApproximateNumberOfMessagesToMove"
            ):
                return last
            if status in ("FAILED", "CANCELLED"):
                return last
        time.sleep(interval_s)
    raise AssertionError(f"move task never reached a settled terminal status within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
