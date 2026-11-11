"""sqs-esm-visibility-timeout-extended-during-processing."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-esm-visibility-timeout-extended-during-processing"
GROUP = "esm-advanced"
SERVICES = ["lambda", "stepfunctions", "sqs"]

_HANDLER_CODE = """
import boto3, json, os, time
sqs = boto3.client("sqs")
RESULTS_QUEUE = os.environ["RESULTS_QUEUE_URL"]
SLEEP_S = float(os.environ.get("SLEEP_S", "20"))

def handler(event, context):
    time.sleep(SLEEP_S)
    for r in event.get("Records", []):
        sqs.send_message(QueueUrl=RESULTS_QUEUE, MessageBody=json.dumps({"body": r["body"]}))
    return {"batchItemFailures": []}
"""

# AWS requires a queue's VisibilityTimeout >= the mapped function's Timeout when CREATING an event
# source mapping (CreateEventSourceMapping rejects the opposite with
# InvalidParameterValueException), so the queue must be created with a VT at least as large as the
# function's Timeout. That constraint only applies at creation time, though -- nothing stops a later
# SetQueueAttributes from lowering the queue's VT again once the mapping already exists. So: create
# with VT == Timeout to satisfy the gate, enable the mapping, then drop the queue's VT to
# LOW_VISIBILITY_TIMEOUT_S, far below the function's sleep. A poller that does NOT actively
# re-extend visibility while the invocation is running would let the message fall back to visible
# within LOW_VISIBILITY_TIMEOUT_S seconds -- many seconds before the function finishes -- which is a
# wide, reliable detection window rather than a margin measured in fractions of a second of dispatch
# overhead.
QUEUE_VISIBILITY_TIMEOUT_S = 15
FUNCTION_TIMEOUT_S = 15
FUNCTION_SLEEP_S = 12
LOW_VISIBILITY_TIMEOUT_S = 4


# timing:real-time — visibility: 4 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-visibility-timeout.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """The Lambda poller extends message visibility while the invocation is still running."""
    sqs = ctx.client("sqs")
    source = _create_queue(ctx, attrs={"VisibilityTimeout": str(QUEUE_VISIBILITY_TIMEOUT_S)})
    results = _create_queue(ctx)
    role_arn = _create_lambda_role(ctx)
    fn_name = _create_function(
        ctx,
        role_arn,
        _HANDLER_CODE,
        timeout=FUNCTION_TIMEOUT_S,
        env={"RESULTS_QUEUE_URL": results["url"], "SLEEP_S": str(FUNCTION_SLEEP_S)},
    )
    _create_esm(ctx, source["arn"], fn_name, BatchSize=1)

    # Lower the queue's VT now that the mapping is enabled -- see the constants comment
    # above for why this has to happen after CreateEventSourceMapping, not at queue
    # creation. A positive control: read it back to confirm the change actually took.
    sqs.set_queue_attributes(QueueUrl=source["url"], Attributes={"VisibilityTimeout": str(LOW_VISIBILITY_TIMEOUT_S)})
    lowered = sqs.get_queue_attributes(QueueUrl=source["url"], AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert int(lowered["VisibilityTimeout"]) == LOW_VISIBILITY_TIMEOUT_S, (
        f"expected the post-creation VisibilityTimeout lowering to take effect, got {lowered}"
    )

    sqs.send_message(QueueUrl=source["url"], MessageBody="vt-extend-probe")

    def _attrs() -> dict[str, str]:
        return sqs.get_queue_attributes(
            QueueUrl=source["url"],
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]

    inflight = _poll_until(_attrs, lambda a: int(a["ApproximateNumberOfMessagesNotVisible"]) >= 1, timeout_s=90, interval_s=1)
    assert int(inflight["ApproximateNumberOfMessages"]) == 0, (
        f"expected the visible count to drop to 0 once the sole message went in-flight, got {inflight}"
    )
    t_inflight = time.monotonic()

    # Watch the source queue (for a premature redelivery) and the results queue (for the
    # function's completion signal) side by side, so we can pin the exact elapsed time from
    # in-flight to completion. The queue's *live* VisibilityTimeout is now LOW_VISIBILITY_TIMEOUT_S
    # (4s), far below the function's 12s sleep: if the poller did NOT actively re-extend it, the
    # message would fall back to visible within 4s while the function is still sleeping. If it
    # DID, completion can only arrive well after LOW_VISIBILITY_TIMEOUT_S has elapsed -- that
    # arrival time is the measured proof, not a guess about dispatch overhead.
    samples = []
    completions: list[dict[str, Any]] = []
    completion_elapsed_s: float | None = None
    completion_deadline = t_inflight + FUNCTION_SLEEP_S + 30.0
    while time.monotonic() < completion_deadline:
        samples.append(_attrs())
        resp = sqs.receive_message(QueueUrl=results["url"], MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for m in resp.get("Messages", []):
            completions.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=results["url"], ReceiptHandle=m["ReceiptHandle"])
        if completions:
            completion_elapsed_s = time.monotonic() - t_inflight
            break
        time.sleep(1)
    for attrs in samples:
        assert int(attrs["ApproximateNumberOfMessages"]) == 0, (
            f"message became visible again ({attrs}) well before the {FUNCTION_SLEEP_S}s function "
            f"execution finished, despite the poller needing to keep re-extending a "
            f"{LOW_VISIBILITY_TIMEOUT_S}s VisibilityTimeout to prevent that"
        )
    assert len(completions) == 1, f"expected exactly one completion, got {completions}"
    assert completions[0]["body"] == "vt-extend-probe", (
        f"expected the completion to echo the original message body 'vt-extend-probe', got {completions[0]!r}"
    )
    assert completion_elapsed_s is not None and completion_elapsed_s > LOW_VISIBILITY_TIMEOUT_S, (
        "expected the total in-flight duration (message receipt to successful processing) to "
        f"exceed the queue's live {LOW_VISIBILITY_TIMEOUT_S}s VisibilityTimeout -- proving the "
        f"poller actively extended it while the function was still running -- but completion "
        f"arrived after only {completion_elapsed_s}s"
    )

    final = _poll_until(_attrs, lambda a: int(a["ApproximateNumberOfMessages"]) == 0 and int(a["ApproximateNumberOfMessagesNotVisible"]) == 0, timeout_s=30)
    assert int(final["ApproximateNumberOfMessages"]) == 0, (
        f"expected the queue to be fully drained (0 visible, 0 in-flight) after processing, got {final}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 2.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_queue(ctx, *, fifo: bool = False, attrs: dict | None = None) -> dict[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-esmq-")
    attributes = dict(attrs or {})
    if fifo:
        name += ".fifo"
        attributes["FifoQueue"] = "true"
    url = sqs.create_queue(QueueName=name, Attributes=attributes)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-esmrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_arns = [
        "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
        "arn:aws:iam::aws:policy/AmazonSQSFullAccess",
    ]
    for arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup() -> None:
        for arn in policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_function(ctx, role_arn: str, code: str, *, timeout: int = 30, env: dict | None = None) -> str:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-esmfn-")
    zip_bytes = _make_zip(code)
    deadline = time.monotonic() + 40.0
    last_err: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                MemorySize=128,
                Environment={"Variables": env or {}},
                Publish=True,
            )
            break
        except ClientError as err:
            if err.response["Error"]["Code"] == "InvalidParameterValueException":
                last_err = err
                time.sleep(2)
                continue
            raise
    else:
        assert last_err is not None
        raise last_err
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(lambda: lam.get_function(FunctionName=name)["Configuration"]["State"], lambda s: s == "Active", timeout_s=60)
    return name


def _create_esm(ctx, event_source_arn: str, function_name: str, **kwargs: Any) -> str:
    lam = ctx.client("lambda")
    resp = lam.create_event_source_mapping(EventSourceArn=event_source_arn, FunctionName=function_name, **kwargs)
    uuid = resp["UUID"]
    ctx.on_cleanup(lambda: lam.delete_event_source_mapping(UUID=uuid))
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=uuid)["State"],
        lambda s: s in ("Enabled", "Disabled"),
        timeout_s=90,
        interval_s=3,
    )
    return uuid


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
