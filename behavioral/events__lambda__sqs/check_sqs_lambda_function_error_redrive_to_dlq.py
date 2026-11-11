"""sqs-lambda-function-error-redrive-to-dlq."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-lambda-function-error-redrive-to-dlq"
GROUP = "state"
SERVICES = ["events", "lambda", "sqs"]

_MANAGED_TAG = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message whose SQS-triggered Lambda always raises moves to the dead-letter queue with
    its body intact once maxReceiveCount is exceeded, and the source queue drains."""
    lam = ctx.client("lambda")
    sqs = ctx.client("sqs")

    # The queue's VisibilityTimeout must be >= the function's Timeout (real AWS requirement for
    # SQS event source mappings), so both are derived from a single explicit function-timeout
    # value rather than two independently-chosen numbers that happen to agree.
    function_timeout_s = 3
    visibility_timeout_s = function_timeout_s + 2

    dlq = _create_queue(ctx)
    src_queue = _create_queue(
        ctx,
        extra_attrs={
            "VisibilityTimeout": str(visibility_timeout_s),
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq["arn"], "maxReceiveCount": 1}),
        },
    )

    role_arn = _create_role(
        ctx,
        "lambda.amazonaws.com",
        inline_policies={
            "esm-perms": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                        "Resource": src_queue["arn"],
                    }
                ],
            }
        },
    )
    assert function_timeout_s < visibility_timeout_s, "function timeout must fit inside the queue's visibility window"
    fn = _create_function(
        ctx,
        role_arn,
        code="def handler(event, context):\n    raise Exception('simulated processing failure')\n",
        timeout=function_timeout_s,
    )

    # Confirm against the actual resulting state (not just a 200) that the function's
    # configured Timeout really is inside the queue's real VisibilityTimeout.
    configured_timeout = lam.get_function_configuration(FunctionName=fn["name"])["Timeout"]
    configured_visibility = int(
        sqs.get_queue_attributes(QueueUrl=src_queue["url"], AttributeNames=["VisibilityTimeout"])[
            "Attributes"
        ]["VisibilityTimeout"]
    )
    assert configured_timeout == function_timeout_s, (
        f"expected function Timeout {function_timeout_s}, got {configured_timeout}"
    )
    assert configured_visibility == visibility_timeout_s, (
        f"expected queue VisibilityTimeout {visibility_timeout_s}, got {configured_visibility}"
    )
    assert configured_timeout < configured_visibility, (
        f"function Timeout {configured_timeout} must be < queue VisibilityTimeout {configured_visibility}"
    )

    mapping = lam.create_event_source_mapping(
        EventSourceArn=src_queue["arn"], FunctionName=fn["name"], BatchSize=10
    )
    uuid = mapping["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=60.0,
        interval_s=2.0,
    )

    sqs.send_message(QueueUrl=src_queue["url"], MessageBody="always-fails")

    dlq_messages = _poll_until(
        lambda: _drain(sqs, dlq["url"], wait=5),
        lambda msgs: len(msgs) >= 1,
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert dlq_messages[0]["Body"] == "always-fails", (
        f"DLQ message body should be the original body, got {dlq_messages[0]['Body']!r}"
    )

    # The message is gone from the source queue once redriven.
    remaining = _poll_until(
        lambda: sqs.get_queue_attributes(
            QueueUrl=src_queue["url"], AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"],
        lambda n: n == "0",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert remaining == "0", (
        f"source queue should be empty once the message is redriven to the DLQ, got {remaining} remaining"
    )


def _error_code(fn):
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _drain(sqs, url, max_msgs=10, wait=2):
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=max_msgs, WaitTimeSeconds=wait)
    return resp.get("Messages", [])


def _create_role(ctx, trust_service, inline_policies=None, managed_arns=None):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _MANAGED_TAG.items()],
    )["Role"]["Arn"]

    def _cleanup():
        for pname in list((inline_policies or {}).keys()):
            try:
                iam.delete_role_policy(RoleName=name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        for marn in (managed_arns or []):
            try:
                iam.detach_role_policy(RoleName=name, PolicyArn=marn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for marn in (managed_arns or []):
        iam.attach_role_policy(RoleName=name, PolicyArn=marn)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _create_function(ctx, role_arn, code, handler="handler.handler", env=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", code)
    zip_bytes = buf.getvalue()
    deadline = time.monotonic() + 40.0
    resp = None
    while True:
        try:
            resp = lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler=handler,
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Environment={"Variables": env or {}},
                Tags=dict(_MANAGED_TAG),
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2,
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_queue(ctx, fifo=False, extra_attrs=None):
    sqs = ctx.client("sqs")
    suffix = ".fifo" if fifo else ""
    name = ctx.unique_name("sim2real-q-") + suffix
    attrs = dict(extra_attrs or {})
    if fifo:
        attrs["FifoQueue"] = "true"
        attrs.setdefault("ContentBasedDeduplication", "true")
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags=dict(_MANAGED_TAG))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
