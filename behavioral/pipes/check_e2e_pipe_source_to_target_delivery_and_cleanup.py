"""e2e-pipe-source-to-target-delivery-and-cleanup."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipe-source-to-target-delivery-and-cleanup"
GROUP = "e2e"
SERVICES = ["pipes"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full pipe lifecycle: create, start, deliver (the target gets the SQS envelope with the exact
    body), stop, delete; the pipe, the role and both queues are then each proven gone."""
    pipes = ctx.client("pipes")
    sqs = ctx.client("sqs")
    iam = ctx.client("iam")

    source_url, source_arn = _create_queue(ctx, "sim2real-pipes-e2e-src-")
    target_url, target_arn = _create_queue(ctx, "sim2real-pipes-e2e-dst-")
    role_arn, role_name, policy_name = _create_pipe_role(ctx, [source_arn], [target_arn])

    pipe_name = ctx.unique_name("sim2real-pipes-e2e-")
    _create_pipe_with_retry(
        ctx,
        Name=pipe_name,
        Source=source_arn,
        Target=target_arn,
        RoleArn=role_arn,
        DesiredState="STOPPED",
        Tags={"sim2real:managed": "true"},
    )

    pipe_deleted = False

    def _cleanup_pipe() -> None:
        nonlocal pipe_deleted
        if not pipe_deleted:
            try:
                pipes.delete_pipe(Name=pipe_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_pipe)

    _wait_for_pipe_state(ctx, pipe_name, {"STOPPED"})

    pipes.start_pipe(Name=pipe_name)
    _wait_for_pipe_state(ctx, pipe_name, {"RUNNING"})

    marker = uuid.uuid4().hex
    sent_body = f"e2e-payload-{marker}"
    sqs.send_message(QueueUrl=source_url, MessageBody=sent_body)

    delivered = _wait_for_body_containing(ctx, target_url, marker, timeout_s=90.0)
    assert delivered is not None, "message never delivered from source to target queue"
    envelope = _sqs_envelope(delivered, sent_body)
    assert envelope.get("eventSource") == "aws:sqs", (
        f"the delivered event is not an SQS-source envelope: {envelope!r}"
    )
    assert envelope.get("eventSourceARN") == source_arn, (
        f"the delivered envelope names source {envelope.get('eventSourceARN')!r}, expected {source_arn!r}"
    )

    pipes.stop_pipe(Name=pipe_name)
    _wait_for_pipe_state(ctx, pipe_name, {"STOPPED"})

    pipes.delete_pipe(Name=pipe_name)
    _wait_for_pipe_deleted(ctx, pipe_name)
    pipe_deleted = True

    _assert_not_found(
        lambda: pipes.describe_pipe(Name=pipe_name), "DescribePipe after delete",
        f"Pipe {pipe_name} does not exist.",
    )

    listed = []
    for page in pipes.get_paginator("list_pipes").paginate(NamePrefix=pipe_name):
        listed.extend(p["Name"] for p in page.get("Pipes", []))
    assert pipe_name not in listed, f"the deleted pipe is still listed by ListPipes: {listed!r}"

    _assert_not_found(
        lambda: pipes.start_pipe(Name=pipe_name), "StartPipe after delete", f"Pipe {pipe_name} does not exist."
    )

    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)
    _assert_role_gone(ctx, role_name, policy_name)

    for url, arn in ((source_url, source_arn), (target_url, target_arn)):
        sqs.delete_queue(QueueUrl=url)
        _assert_queue_gone(ctx, url, arn.rsplit(":", 1)[-1])


def _create_queue(ctx, prefix: str) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name(prefix),
        tags={"sim2real:managed": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _safe_delete_queue(ctx, url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


_NO_QUEUE = "AWS.SimpleQueueService.NonExistentQueue"


def _safe_delete_queue(ctx, url: str) -> None:
    try:
        ctx.client("sqs").delete_queue(QueueUrl=url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (_NO_QUEUE, "QueueDoesNotExist"):
            raise


def _poll_refused(fn, what: str, timeout_s: float = 90.0, interval_s: float = 3.0):
    """Deletes in SQS and IAM are eventually consistent: poll until the call is refused and
    return its (code, HTTP status, message); a call still accepted at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return (
                exc.response["Error"].get("Code"),
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response["Error"].get("Message") or "",
            )
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} still succeeds {timeout_s}s after the delete: {result!r}")
        time.sleep(interval_s)


def _assert_refused(refused, what: str, code: str, status: int) -> None:
    got_code, got_status, message = refused
    assert got_code == code, f"{what}: expected {code}, got {got_code!r}"
    assert isinstance(got_status, int) and got_status // 100 == status // 100, (
        f"{what}: expected HTTP {status // 100}xx, got {got_status!r}"
    )
    assert message.strip(), f"{what}: the message is empty"


def _assert_queue_gone(ctx, url: str, name: str) -> None:
    sqs = ctx.client("sqs")
    expected_message = "The specified queue does not exist."
    refused = _poll_refused(lambda: sqs.get_queue_url(QueueName=name), f"GetQueueUrl({name})")
    _assert_refused(refused, f"GetQueueUrl on deleted queue {name}", _NO_QUEUE, 400)
    assert refused[2] == expected_message, f"expected the message {expected_message!r}, got {refused[2]!r}"
    listed = sqs.list_queues(QueueNamePrefix=name).get("QueueUrls", [])
    assert url not in listed, f"deleted queue {name} is still listed by ListQueues: {listed!r}"
    refused = _poll_refused(lambda: sqs.send_message(QueueUrl=url, MessageBody="x"), f"SendMessage({name})")
    _assert_refused(refused, f"SendMessage to deleted queue {name}", _NO_QUEUE, 400)
    assert refused[2] == expected_message, f"expected the message {expected_message!r}, got {refused[2]!r}"


def _create_pipe_role(ctx, source_arns: list[str], target_arns: list[str]) -> tuple[str, str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-pipes-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pipes.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = ctx.unique_name("sim2real-pipes-policy-")
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": source_arns,
            },
            {"Effect": "Allow", "Action": ["sqs:SendMessage"], "Resource": target_arns},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_role(ctx, role_name, policy_name))
    return role_arn, role_name, policy_name


def _safe_delete_role(ctx, role_name: str, policy_name: str) -> None:
    iam = ctx.client("iam")
    for fn in (
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name),
        lambda: iam.delete_role(RoleName=role_name),
    ):
        try:
            fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise


def _assert_role_gone(ctx, role_name: str, policy_name: str) -> None:
    iam = ctx.client("iam")
    got_code, got_status, got_message = _poll_refused(lambda: iam.get_role(RoleName=role_name), f"GetRole({role_name})")
    _assert_refused((got_code, got_status, got_message), f"GetRole on deleted role {role_name}", "NoSuchEntity", 404)
    expected_message = f"The role with name {role_name} cannot be found."
    assert got_message == expected_message, f"expected the message {expected_message!r}, got {got_message!r}"
    listed = [
        r["RoleName"] for page in iam.get_paginator("list_roles").paginate() for r in page.get("Roles", [])
    ]
    assert role_name not in listed, f"deleted role {role_name} is still listed by ListRoles"
    doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    })
    got_code, got_status, got_message = _poll_refused(
        lambda: iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=doc),
        f"PutRolePolicy({role_name})",
    )
    _assert_refused(
        (got_code, got_status, got_message), f"PutRolePolicy on deleted role {role_name}", "NoSuchEntity", 404,
    )
    expected_message = f"The role with name {role_name} cannot be found."
    assert got_message == expected_message, f"expected the message {expected_message!r}, got {got_message!r}"


def _create_pipe_with_retry(ctx, timeout_s: float = 60.0, **kwargs):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return pipes.create_pipe(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _wait_for_pipe_state(ctx, name: str, target_states: set[str], timeout_s: float = 120.0, interval_s: float = 3.0):
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = pipes.describe_pipe(Name=name)
        last = resp["CurrentState"]
        if last in target_states:
            return resp
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} never reached {target_states}, last state was {last}")


def _wait_for_pipe_deleted(ctx, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    pipes = ctx.client("pipes")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            pipes.describe_pipe(Name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        time.sleep(interval_s)
    raise AssertionError(f"pipe {name} was never fully deleted")


def _wait_for_body_containing(ctx, queue_url: str, marker: str, timeout_s: float = 90.0) -> str | None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if marker in msg["Body"]:
                return msg["Body"]
    return None


def _client_error(fn, what) -> dict:
    """Run a call that must be refused; return its error response. An accepted call raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"{what} must be refused, but it succeeded: {result!r}")


def _assert_not_found(fn, what: str, expected_message: str) -> None:
    response = _client_error(fn, what)
    code = response["Error"]["Code"]
    assert code == "NotFoundException", f"{what}: expected NotFoundException, got {code!r}"
    status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected HTTP 4xx, got {status!r}"
    message = response["Error"].get("Message") or ""
    assert message == expected_message, f"{what}: expected the message {expected_message!r}, got {message!r}"


def _sqs_envelope(delivered: str, sent_body: str) -> dict:
    """The one SQS-source event in the target message whose body is exactly `sent_body`."""
    try:
        parsed = json.loads(delivered)
    except ValueError as exc:
        raise AssertionError(f"the target message is not a JSON event envelope: {delivered!r}") from exc
    events = parsed if isinstance(parsed, list) else [parsed]
    matching = [e for e in events if isinstance(e, dict) and e.get("body") == sent_body]
    assert len(matching) == 1, (
        f"expected exactly one envelope whose body is {sent_body!r}, got {delivered!r}"
    )
    return matching[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
