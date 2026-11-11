"""create-event-source-mapping-duplicate-conflict."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-source-mapping-duplicate-conflict"
GROUP = "esm"
SERVICES = ["lambda"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second mapping for the identical (EventSourceArn, FunctionName) pair must
    fail, not create a duplicate -- and once the original mapping is gone, the identical call
    must succeed again, proving the conflict was about the existing duplicate and nothing else."""
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-lambda-esm-dup-")
    _create_function(ctx, lam, name=name, role_arn=_create_sqs_capable_role(ctx))
    _wait_active(lam, name)

    _queue_url, queue_arn = _create_queue(ctx)

    create_resp = _create_event_source_mapping(
        ctx, lam, FunctionName=name, EventSourceArn=queue_arn
    )
    uuid = create_resp["UUID"]
    _wait_esm_state(lam, uuid, states=("Enabled", "Disabled"))

    # Second create for the same (source, function) pair -- asserted directly (no
    # retry wrapper) because a conflict is exactly what we want to observe.
    code, message = _error_code(
        lambda: lam.create_event_source_mapping(FunctionName=name, EventSourceArn=queue_arn)
    )
    assert code == "ResourceConflictException", f"expected ResourceConflictException, got {code}"
    expected = (
        f'An event source mapping with SQS arn (" {queue_arn} ") and function (" {name} ") '
        f"already exists. Please update or delete the existing mapping with UUID {uuid}"
    )
    assert message == expected, (
        f"the duplicate CreateEventSourceMapping returned message {message!r}, expected {expected!r}"
    )

    # Independent read (ListEventSourceMappings, not the failed CreateEventSourceMapping's own
    # response): the rejected duplicate must not have sneaked a second mapping onto this pair.
    survivors = lam.list_event_source_mappings(FunctionName=name, EventSourceArn=queue_arn)[
        "EventSourceMappings"
    ]
    survivor_uuids = [m["UUID"] for m in survivors]
    assert survivor_uuids == [uuid], (
        f"expected exactly the original mapping {uuid!r} to survive the duplicate create "
        f"attempt, found {survivor_uuids!r}"
    )

    # Restore: remove the mapping that was blocking creation, prove it is gone by an independent
    # read, then prove the identical call now succeeds -- the conflict was about the existing
    # duplicate, not a standing rejection of this (source, function) pair.
    lam.delete_event_source_mapping(UUID=uuid)
    _wait_esm_gone(lam, uuid)

    recreate_resp = _create_event_source_mapping(
        ctx, lam, FunctionName=name, EventSourceArn=queue_arn
    )
    new_uuid = recreate_resp["UUID"]
    assert new_uuid != uuid, (
        f"expected the recreate after deleting the original to mint a new UUID, "
        f"got the same {uuid!r} back"
    )

    # Terminal read via a third, independent operation (GetEventSourceMapping): the recreated
    # mapping is really on file for this pair, not just echoed by the CreateEventSourceMapping
    # response.
    readback = lam.get_event_source_mapping(UUID=new_uuid)
    assert readback.get("EventSourceArn") == queue_arn, (
        f"expected the recreated mapping to read back with EventSourceArn {queue_arn!r}, "
        f"got {readback.get('EventSourceArn')!r}"
    )


_DEFAULT_HANDLER_SRC = """
import json

def handler(event, context):
    if isinstance(event, dict) and event.get("fail"):
        raise Exception("intentional-failure: " + str(event.get("fail")))
    return {"echo": event}
"""


def _make_zip(src: str = _DEFAULT_HANDLER_SRC, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, src)
    return buf.getvalue()


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) from the ClientError it raises.

    An unexpected success raises, so a target that accepts the duplicate reads as the defect it is.
    """
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call unexpectedly succeeded")


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=1.5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _cleanup_fn(ctx, lam, name: str) -> None:
    """Delete the function and the log group Lambda implicitly creates for it."""
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{name}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(lam, name: str, timeout_s: float = 90, interval_s: float = 1.5):
    """Poll until State settles at Active or Failed.

    Deliberately does NOT raise on Failed: a Failed function surfaces as a real service
    error on the next call.
    """
    return _poll_until(
        lambda: lam.get_function_configuration(FunctionName=name),
        lambda cfg: cfg.get("State") in ("Active", "Failed"),
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"function {name} to leave Pending",
    )


def _create_function(
    ctx,
    lam,
    role_arn: str,
    name=None,
    src: str = _DEFAULT_HANDLER_SRC,
    handler: str = "index.handler",
    runtime: str = "python3.12",
    timeout: int = 15,
    memory: int = 128,
    env: dict | None = None,
    **kwargs,
):
    """CreateFunction with teardown registered up front and bounded retry on IAM
    role propagation (the classic "cannot be assumed by Lambda" race)."""
    name = name or ctx.unique_name("sim2real-behav-lambda-fn-")
    params = dict(
        FunctionName=name,
        Runtime=runtime,
        Role=role_arn,
        Handler=handler,
        Code={"ZipFile": _make_zip(src)},
        Timeout=timeout,
        MemorySize=memory,
        Publish=False,
    )
    if env is not None:
        params["Environment"] = {"Variables": env}
    params.update(kwargs)

    ctx.on_cleanup(lambda: _cleanup_fn(ctx, lam, name))
    last_exc = None
    for _ in range(8):
        try:
            return lam.create_function(**params)
        except ClientError as exc:
            msg = str(exc)
            if "cannot be assumed" in msg or (
                "InvalidParameterValueException" in msg and "role" in msg.lower()
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


def _create_sqs_capable_role(ctx) -> str:
    """A dedicated lambda-trusting role carrying AWSLambdaSQSQueueExecutionRole.

    CreateEventSourceMapping validates at create time that the execution role can
    call ReceiveMessage, so the plain basic-execution role is not sufficient.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-lambda-esm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_queue(ctx) -> tuple[str, str]:
    """A real SQS queue to act as the event source. Returns (queue_url, queue_arn)."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-lambda-src-"))["QueueUrl"]
    ctx.on_cleanup(lambda: _ignore(lambda: sqs.delete_queue(QueueUrl=url)))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
            "ResourceNotFoundException",
        ):
            raise


def _create_event_source_mapping(ctx, lam, **params) -> dict:
    """CreateEventSourceMapping with bounded retry on IAM policy propagation.

    Lambda validates that the execution role can call ReceiveMessage at create time.
    When the role's SQS policy was only just attached, that validation fails with
    InvalidParameterValueException until IAM propagates -- a startup race, not a
    behavioral difference. Retries are bounded and only for that specific message.
    """
    deadline = time.monotonic() + 120
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = lam.create_event_source_mapping(**params)
            uuid = resp["UUID"]
            ctx.on_cleanup(lambda: _ignore(lambda: lam.delete_event_source_mapping(UUID=uuid)))
            return resp
        except ClientError as exc:
            if "does not have permissions" in str(exc) or "ReceiveMessage" in str(exc):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(
        f"CreateEventSourceMapping never passed role validation within 120s: {last_exc}"
    )


def _wait_esm_state(lam, uuid: str, states: tuple[str, ...], timeout_s: float = 90, interval_s: float = 1.5):
    return _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid),
        lambda m: m.get("State") in states,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"mapping {uuid} to reach one of {states}",
    )


def _wait_esm_gone(lam, uuid: str, timeout_s: float = 90, interval_s: float = 1.5):
    def _probe():
        try:
            return lam.get_event_source_mapping(UUID=uuid)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return None
            raise

    return _poll_until(
        _probe,
        lambda m: m is None,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"mapping {uuid} to be deleted",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
